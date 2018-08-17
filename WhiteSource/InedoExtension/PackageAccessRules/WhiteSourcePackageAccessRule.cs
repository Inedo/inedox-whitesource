using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Security;
using System.Threading.Tasks;
using Inedo.Diagnostics;
using Inedo.Documentation;
using Inedo.Extensibility.PackageAccessRules;
using Inedo.Feeds;
using Inedo.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Inedo.Extensions.WhiteSource.PackageAccessRules
{
    [DisplayName("WhiteSource")]
    [Description("Verifies with WhiteSource that a package is allowed to be downloaded.")]
    [PersistFrom("WhiteSource.PackageAccessRules.WhiteSourcePackageAccessRule,WhiteSource")]
    public sealed class WhiteSourcePackageAccessRule : PackageAccessRule
    {
        [Required]
        [DisplayName("Token")]
        [Persistent(Encrypted = true)]
        public SecureString Token { get; set; }

        public override async Task<PackageAccessPolicy> GetPackageAccessPolicyAsync(IPackageIdentifier package)
        {
            if (!(package is IExtendedPackageIdentifier extPackage))
                return PackageAccessPolicy.Allowed;

            var sha1 = extPackage.GetPackageHash(PackageHashAlgorithm.SHA1);
            if (sha1 == null)
                return new PackageAccessPolicy(false, $"Package {package.Name} {package.Version} does not have a SHA1 hash computed. Run the Feed Cleanup task to generate one.");

            var request = WebRequest.CreateHttp("https://saas.whitesourcesoftware.com/agent");
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded; charset=utf8";
            request.ServicePoint.Expect100Continue = false;

            using (var requestStream = await request.GetRequestStreamAsync().ConfigureAwait(false))
            using (var writer = new StreamWriter(requestStream, InedoLib.UTF8Encoding))
            {
                writer.Write("type=CHECK_POLICY_COMPLIANCE&agent=generic&agentVersion=2.4.1&pluginVersion=");
                writer.Write(Uri.EscapeDataString(typeof(WhiteSourcePackageAccessRule).Assembly.GetName().Version.ToString(3)));
                writer.Write("&token=");
                writer.Write(Uri.EscapeDataString(AH.Unprotect(this.Token)));
                writer.Write("&timeStamp=");
                writer.Write(GetTimestamp(DateTime.UtcNow));
                writer.Write("&diff=");
                writer.Write(Uri.EscapeDataString(GetDiff(extPackage)));
            }

            JObject envelope;
            try
            {
                using (var response = (HttpWebResponse)await request.GetResponseAsync().ConfigureAwait(false))
                using (var reader = new StreamReader(response.GetResponseStream(), InedoLib.UTF8Encoding))
                {
                    try
                    {
                        using (var jsonReader = new JsonTextReader(reader))
                        {
                            envelope = JObject.Load(jsonReader);
                        }
                    }
                    catch (Exception ex)
                    {
                        this.LogError("Invalid data from WhiteSource; expected JSON", ex.ToString());
                        return new PackageAccessPolicy(false, "Invalid data from WhiteSource. See the ProGet error logs for more information.");
                    }
                }
            }
            catch (WebException ex)
            {
                if (ex.Response is HttpWebResponse response)
                {
                    this.LogError(
                        $"HTTP {response.StatusCode} from WhiteSource",
                        "Response body:" + Environment.NewLine + new StreamReader(response.GetResponseStream(), InedoLib.UTF8Encoding).ReadToEnd()
                    );
                }

                return new PackageAccessPolicy(false, "Error communicating with WhiteSource for package verification. See the ProGet error logs for more information.");
            }

            if ((int)envelope.Property("status") == 1)
            {
                var data = JObject.Parse((string)envelope.Property("data"));
                var policies = from p in data.Descendants().OfType<JProperty>()
                               where p.Name == "policy" && p.Value is JObject
                               select (JObject)p.Value;

                foreach (var policy in policies)
                {
                    if ((string)policy.Property("actionType") == "Reject")
                        return new PackageAccessPolicy(false, $"Package rejected due to \"{policy.Property("displayName")?.Value}\" WhiteSource policy.");
                }

                return PackageAccessPolicy.Allowed;
            }

            return new PackageAccessPolicy(false, "WhiteSource returned error when checking policies: " + (string)envelope.Property("message"));
        }

        private static string GetDiff(IExtendedPackageIdentifier package)
        {
            var coordinates = new JObject(
                new JProperty("artifactId", package.Name),
                new JProperty("version", package.Version.ToString())
            );
            if (!string.IsNullOrEmpty(package.Group))
                coordinates["groupId"] = package.Group;

            var sha1 = package.GetPackageHash(PackageHashAlgorithm.SHA1);
            var sha1Hex = string.Join(string.Empty, sha1.Select(b => b.ToString("x2")));

            var dependency = new JObject(
                new JProperty("artifactId", package.Name),
                new JProperty("version", package.Version),
                new JProperty("sha1", sha1Hex),
                new JProperty("checksums",
                    new JObject(
                        new JProperty("SHA1", sha1Hex)
                    )
                )
            );
            if (!string.IsNullOrEmpty(package.Group))
                dependency["groupId"] = package.Group;

            var md5 = package.GetPackageHash(PackageHashAlgorithm.MD5);
            if (md5 != null)
                dependency["checksums"]["MD5"] = string.Join(string.Empty, md5.Select(b => b.ToString("x2")));

            using (var textWriter = new StringWriter())
            {
                using (var jsonWriter = new JsonTextWriter(textWriter) { CloseOutput = false })
                {
                    new JArray(new JObject(new JProperty("coordinates", coordinates), new JProperty("dependencies", new JArray(dependency)))).WriteTo(jsonWriter);
                }

                return textWriter.ToString();
            }
        }
        private static long GetTimestamp(DateTime d) => (long)(d - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
    }
}
