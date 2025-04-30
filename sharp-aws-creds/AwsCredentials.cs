namespace sharp_aws_creds;

public class AwsCredentials
{
    public string AccessKeyId { get; set; }
    public string SecretAccessKey { get; set; }
    public string SessionToken { get; set; }
    public DateTime Expiration { get; set; }
}