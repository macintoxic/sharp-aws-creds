using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;

namespace sharp_aws_creds;

public class OktaClient
{
    private readonly HttpClient _httpClient;
    private readonly string _oktaOrgUrl;
    private string _sessionToken;
    private readonly JsonSerializerOptions _jsonOptions;

    public OktaClient(string oktaOrgUrl)
    {
        _oktaOrgUrl = oktaOrgUrl.TrimEnd('/');
        _httpClient = new HttpClient();
        _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "GimmeAwsCreds");

        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
    }

    private async Task AuthenticateWithOkta(string username)
    {
        Console.Write("Enter your Okta password: ");
        var password = ReadPassword();

        var authRequest = new AuthRequest
        {
            Username = username,
            Password = password,
            Options = new AuthOptions
            {
                MultiOptionalFactorEnroll = false,
                WarnBeforePasswordExpired = true
            }
        };

        var response = await _httpClient.PostAsync(
            $"{_oktaOrgUrl}/api/v1/authn",
            new StringContent(
                JsonSerializer.Serialize(authRequest, _jsonOptions),
                Encoding.UTF8, "application/json"));

        var content = await response.Content.ReadAsStringAsync();
        var authResult = JsonSerializer.Deserialize<JsonElement>(content);

        if (authResult.GetProperty("status").GetString() == "SUCCESS")
        {
            _sessionToken = authResult.GetProperty("sessionToken").GetString()!;
        }
        else if (authResult.GetProperty("status").GetString() == "MFA_REQUIRED")
        {
            _sessionToken = await HandleMfaChallenge(authResult);
        }
        else
        {
            throw new Exception("Authentication failed");
        }
    }

    private async Task<string> HandlePushNotification(JsonElement factor, string stateToken)
    {
        var request = new StateTokenRequest { StateToken = stateToken };

        var verifyResponse = await _httpClient.PostAsync(
            factor.GetProperty("_links").GetProperty("verify").GetProperty("href").GetString(),
            new StringContent(
                JsonSerializer.Serialize(request, _jsonOptions),
                Encoding.UTF8,
                "application/json"));

        var content = await verifyResponse.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);

        Console.WriteLine("Push notification sent. Please approve it on your device...");

        while (result.GetProperty("status").GetString() == "MFA_CHALLENGE")
        {
            await Task.Delay(2000);
            verifyResponse = await _httpClient.PostAsync(
                result.GetProperty("_links").GetProperty("next").GetProperty("href").GetString(),
                new StringContent(
                    JsonSerializer.Serialize(request, _jsonOptions),
                    Encoding.UTF8,
                    "application/json"));
            content = await verifyResponse.Content.ReadAsStringAsync();
            result = JsonSerializer.Deserialize<JsonElement>(content);
        }

        return result.GetProperty("sessionToken").GetString()!;
    }

    private async Task<string> HandleTotp(JsonElement factor, string stateToken)
    {
        Console.Write("Enter your verification code: ");
        var code = Console.ReadLine();

        var verifyRequest = new VerifyFactorRequest
        {
            StateToken = stateToken,
            PassCode = code!
        };

        var verifyResponse = await _httpClient.PostAsync(
            factor.GetProperty("_links").GetProperty("verify").GetProperty("href").GetString(),
            new StringContent(
                JsonSerializer.Serialize(verifyRequest, _jsonOptions),
                Encoding.UTF8,
                "application/json"));

        var content = await verifyResponse.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);

        if (result.GetProperty("status").GetString() != "SUCCESS")
        {
            throw new Exception("MFA verification failed");
        }

        return result.GetProperty("sessionToken").GetString()!;
    }

    public async Task<AwsCredentials> GetAwsCredentials(string username, string awsApp, string awsRole)
    {
        // 1. Authenticate with Okta
        await AuthenticateWithOkta(username);

        // 2. Get SAML assertion
        var samlAssertion = await GetSamlAssertion(awsApp);

        // 3. Use SAML to get AWS credentials
        return await GetAwsCredentialsWithSaml(samlAssertion, awsRole);
    }


    private async Task<string> HandleMfaChallenge(JsonElement authResult)
    {
        var factors = authResult.GetProperty("_embedded").GetProperty("factors");

        // Display available factors
        Console.WriteLine("\nAvailable MFA methods:");
        var factorList = new List<JsonElement>();
        var i = 1;
        foreach (var factor in factors.EnumerateArray())
        {
            factorList.Add(factor);
            Console.WriteLine($"{i}. {factor.GetProperty("factorType").GetString()}");
            i++;
        }

        Console.Write("\nSelect MFA method (number): ");
        var selection = int.Parse(Console.ReadLine()!) - 1;
        var selectedFactor = factorList[selection];

        // Handle push notification
        if (selectedFactor.GetProperty("factorType").GetString() == "push")
        {
            return await HandlePushNotification(selectedFactor, authResult.GetProperty("stateToken").GetString()!);
        }
        // Handle TOTP

        if (selectedFactor.GetProperty("factorType").GetString() == "token:software:totp")
        {
            return await HandleTotp(selectedFactor, authResult.GetProperty("stateToken").GetString()!);
        }

        throw new Exception("Unsupported MFA method");
    }

    private async Task<AwsCredentials> GetAwsCredentialsWithSaml(string samlAssertion, string roleArn)
    {
        try
        {
            // 1. First decode HTML entities (like &#x2b; to +)
            var htmlDecoded = System.Web.HttpUtility.HtmlDecode(samlAssertion);

            // 2. Replace URL-safe characters back to their original form
            var base64Fixed = htmlDecoded
                .Replace('-', '+')
                .Replace('_', '/');

            // Add padding if needed
            switch (base64Fixed.Length % 4)
            {
                case 2: base64Fixed += "=="; break;
                case 3: base64Fixed += "="; break;
            }

            // 3. Base64 decode
            var bytes = Convert.FromBase64String(base64Fixed);
            var decodedSamlAssertion = System.Text.Encoding.UTF8.GetString(bytes);

            // For debugging - log the decoded assertion
            Console.WriteLine("Decoded SAML assertion:");
            Console.WriteLine(decodedSamlAssertion);

            // Parse the SAML assertion to get the role ARNs
            var doc = new XmlDocument();
            doc.LoadXml(decodedSamlAssertion);

            // Add namespace manager for SAML
            var manager = new XmlNamespaceManager(doc.NameTable);
            manager.AddNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

            // Get the role attribute values
            var roleAttribute =
                doc.SelectNodes(
                    "//saml2:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']/saml2:AttributeValue",
                    manager);

            if (roleAttribute == null || roleAttribute.Count == 0)
            {
                throw new Exception("No AWS roles found in SAML assertion");
            }

            // Get all available roles
            var availableRoles = new List<(string RoleArn, string PrincipalArn)>();
            foreach (XmlNode attr in roleAttribute)
            {
                var parts = attr.InnerText.Split(',');
                var currentRoleArn = parts.First(p => p.Contains(":role/"));
                var principalArn = parts.First(p => p.Contains(":saml-provider/"));
                availableRoles.Add((currentRoleArn, principalArn));
            }

            // Find the matching role if one was specified
            var selectedRole =
                availableRoles.FirstOrDefault(r => string.IsNullOrEmpty(roleArn) || r.RoleArn == roleArn);
            if (selectedRole == default)
            {
                if (string.IsNullOrEmpty(roleArn))
                {
                    // If no role was specified, use the first one
                    selectedRole = availableRoles[0];
                }
                else
                {
                    throw new Exception(
                        $"Specified role {roleArn} not found in SAML assertion. Available roles: {string.Join(", ", availableRoles.Select(r => r.RoleArn))}");
                }
            }

            Console.WriteLine($"Using Role ARN: {selectedRole.RoleArn}");
            Console.WriteLine($"Using Principal ARN: {selectedRole.PrincipalArn}");

            // Get session duration if specified in SAML assertion
            const int durationSeconds = 14400; // default 1 hour
            // var durationAttribute = doc.SelectSingleNode("//saml2:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/SessionDuration']/saml2:AttributeValue", manager);
            // if (durationAttribute != null && int.TryParse(durationAttribute.InnerText, out int requestedDuration))
            // {
            //     durationSeconds = requestedDuration;
            // }

            var stsClient = new AmazonSecurityTokenServiceClient();

            var response = await stsClient.AssumeRoleWithSAMLAsync(new AssumeRoleWithSAMLRequest
            {
                RoleArn = selectedRole.RoleArn,
                PrincipalArn = selectedRole.PrincipalArn,
                SAMLAssertion = htmlDecoded, // Use the HTML decoded assertion
                DurationSeconds = durationSeconds
            });

            return new AwsCredentials
            {
                AccessKeyId = response.Credentials.AccessKeyId,
                SecretAccessKey = response.Credentials.SecretAccessKey,
                SessionToken = response.Credentials.SessionToken,
                Expiration = response.Credentials.Expiration
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing SAML assertion: {ex.Message}");
            Console.WriteLine($"Stack trace: {ex.StackTrace}");
            throw;
        }
    }

    private async Task<string> GetSamlAssertion(string awsAppUrl)
    {
        if (!IsValidUrl(awsAppUrl))
            throw new ArgumentException("Invalid url");
        
        var response = await _httpClient.GetAsync(
            $"{awsAppUrl}?sessionToken={_sessionToken}");

        var html = await response.Content.ReadAsStringAsync();

        return SamlParser.ExtractSamlResponseWithHtmlParsing(html);
       
    }

    private bool IsValidUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        return uri.Scheme == "https" && uri.Host.EndsWith(".okta.com") || uri.Host.EndsWith(".amazonaws.com");

    }
    

    private static string ReadPassword()
    {
        var password = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter)
                break;
            if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                password.Length--;
            else
                password.Append(key.KeyChar);
        }

        Console.WriteLine();
        return password.ToString();
    }
}