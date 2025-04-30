using System.CommandLine;

namespace sharp_aws_creds
{
    public class Program
    {
        static async Task<int> Main(string[] args)
        {
         
            var oktaOrgOption = new Option<string>(
                    "--okta-org",
                    "Your Okta organization URL")
                { IsRequired = true };

            var usernameOption = new Option<string>(
                    "--username",
                    "Your Okta username")
                { IsRequired = true };

            var awsAppOption = new Option<string>(
                    "--aws-app",
                    "AWS app link from Okta")
                { IsRequired = true };

            var awsRoleOption = new Option<string>(
                    "--aws-role",
                    "AWS role to assume")
                { IsRequired = true };

            var rootCommand = new RootCommand("Get temporary AWS credentials through Okta SSO")
            {
                oktaOrgOption,
                usernameOption,
                awsAppOption,
                awsRoleOption
            };


            rootCommand.SetHandler(async (string oktaOrg, string username, string awsApp, string awsRole) =>
            {
                try
                {
                    var client = new OktaClient(oktaOrg);
                    var credentials = await client.GetAwsCredentials(username, awsApp, awsRole);
                    await WriteAwsCredentials(credentials);
                    Console.WriteLine("AWS credentials successfully obtained and saved!");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                    Environment.Exit(1);
                }
            }, oktaOrgOption, usernameOption, awsAppOption, awsRoleOption);

            return await rootCommand.InvokeAsync(args);
        }

        private static async Task WriteAwsCredentials(AwsCredentials creds)
        {
            // Write to ~/.aws/credentials
            var configPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".aws",
                "credentials");

            var config = $@"[default]
aws_access_key_id = {creds.AccessKeyId}
aws_secret_access_key = {creds.SecretAccessKey}
aws_session_token = {creds.SessionToken}
";
            await File.WriteAllTextAsync(configPath, config);
        }
    }
}