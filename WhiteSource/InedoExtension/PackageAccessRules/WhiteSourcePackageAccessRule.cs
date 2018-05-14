using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
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

        #region Messy reflection rubbish
        private static readonly Type PackageHashAlgorithm = Type.GetType("Inedo.ProGet.Feeds.PackageHashAlgorithm,ProGetCoreEx");
        private static readonly object PackageHashAlgorithm_SHA1 = Enum.Parse(PackageHashAlgorithm, "SHA1");
        private static readonly Type IExtendedPackageIdentifier = Type.GetType("Inedo.ProGet.Feeds.IExtendedPackageIdentifier,ProGetCoreEx");
        private static readonly MethodInfo IExtendedPackageIdentifier_GetPackageHash = IExtendedPackageIdentifier.GetMethod("GetPackageHash", new[] { PackageHashAlgorithm });
        private static readonly PropertyInfo IExtendedPackageIdentifier_Modified = IExtendedPackageIdentifier.GetProperty("Modified", typeof(DateTimeOffset?));
        #endregion

        public override async Task<PackageAccessPolicy> GetPackageAccessPolicyAsync(IPackageIdentifier package)
        {
            if (!IExtendedPackageIdentifier.IsAssignableFrom(package.GetType()))
                return PackageAccessPolicy.Allowed;

            var sha1 = (byte[])IExtendedPackageIdentifier_GetPackageHash.Invoke(package, new[] { PackageHashAlgorithm_SHA1 });
            if (sha1 == null)
                return new PackageAccessPolicy(false, $"Package {package.Name} {package.Version} does not have a SHA1 hash computed. Run the Feed Cleanup task to generate one.");

            var request = WebRequest.CreateHttp("https://saas.whitesourcesoftware.com/agent");
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded; charset=utf8";
            request.ServicePoint.Expect100Continue = false;

            using (var requestStream = await request.GetRequestStreamAsync().ConfigureAwait(false))
            using (var writer = new StreamWriter(requestStream, InedoLib.UTF8Encoding))
            {
                writer.Write("type=CHECK_POLICIES&agent=generic&agentVersion=1.0&token=");
                writer.Write(Uri.EscapeDataString(AH.Unprotect(this.Token)));
                writer.Write("&timeStamp=");
                writer.Write(GetTimestamp(DateTime.UtcNow));
                writer.Write("&diff=");
                writer.Write(Uri.EscapeDataString(GetDiff(package.Name, package.Version, sha1, ((DateTimeOffset?)IExtendedPackageIdentifier_Modified.GetValue(package)) ?? DateTimeOffset.Now)));
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

        private static string GetDiff(string name, object version, byte[] sha1, DateTimeOffset lastModified)
        {
            using (var textWriter = new StringWriter())
            {
                using (var jsonWriter = new JsonTextWriter(textWriter) { CloseOutput = false })
                {
                    new JArray(
                        new JObject(
                            new JProperty("coordinates",
                                new JObject(
                                    new JProperty("artifactId", name),
                                    new JProperty("version", version.ToString())
                                )
                            ),
                            new JProperty("dependencies",
                                new JArray(
                                    new JObject(
                                        new JProperty("artifactId", name),
                                        new JProperty("sha1", string.Join(string.Empty, sha1.Select(b => b.ToString("x2")))),
                                        new JProperty("otherPlatformSha1", string.Empty),
                                        new JProperty("systemPath", string.Empty),
                                        new JProperty("optional", false),
                                        new JProperty("children", new JArray()),
                                        new JProperty("exclusions", new JArray()),
                                        new JProperty("licenses", new JArray()),
                                        new JProperty("copyrights", new JArray()),
                                        new JProperty("lastModified", lastModified.UtcDateTime.ToString("MMM' 'd', 'yyyy' 'h':'mm':'ss' 'tt"))
                                    )
                                )
                            )
                        )
                    ).WriteTo(jsonWriter);
                }

                return textWriter.ToString();
            }
        }
        private static long GetTimestamp(DateTime d) => (long)(d - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
    }
}
