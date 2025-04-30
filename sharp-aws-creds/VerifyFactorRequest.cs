namespace sharp_aws_creds;

public class VerifyFactorRequest
{
    public string StateToken { get; set; }
    public string PassCode { get; set; }
}