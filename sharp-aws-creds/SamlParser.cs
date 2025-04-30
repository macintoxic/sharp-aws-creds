using System.Text.RegularExpressions;
using HtmlAgilityPack;

namespace sharp_aws_creds;

public class SamlParser
{
    // Approach 1: Using Regex
    public static string ExtractSamlResponseWithRegex(string html)
    {
        try
        {
            var pattern = """<input\s+name="SAMLResponse"\s+type="hidden"\s+value="([^"]+)"\s*/>""";
            var match = Regex.Match(html, pattern);
            
            if (match is { Success: true, Groups.Count: > 1 })
            {
                return match.Groups[1].Value;
            }
            
            throw new Exception("SAML Response not found in HTML");
        }
        catch (Exception ex)
        {
            throw new Exception($"Error extracting SAML Response: {ex.Message}");
        }
    }

    // Approach 2: Using HTML Agility Pack (more robust)
    public static string ExtractSamlResponseWithHtmlParsing(string html)
    {
        try
        {
            var doc = new HtmlDocument();
            doc.LoadHtml(html);

            var samlInput = doc.DocumentNode.SelectSingleNode("//input[@name='SAMLResponse']");
            
            if (samlInput != null)
            {
                return samlInput.GetAttributeValue("value", string.Empty);
            }
            
            throw new Exception("SAML Response not found in HTML");
        }
        catch (Exception ex)
        {
            throw new Exception($"Error extracting SAML Response: {ex.Message}");
        }
    }
}