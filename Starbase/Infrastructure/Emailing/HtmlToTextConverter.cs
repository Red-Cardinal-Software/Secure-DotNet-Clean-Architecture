using System.Text;
using System.Text.RegularExpressions;
using HtmlAgilityPack;

namespace Infrastructure.Emailing;

/// <summary>
/// Converts HTML content to plain text for email accessibility.
/// </summary>
public static partial class HtmlToTextConverter
{
    /// <summary>
    /// Converts HTML to plain text, preserving basic structure.
    /// </summary>
    /// <param name="html">The HTML content to convert.</param>
    /// <returns>Plain text representation of the HTML.</returns>
    public static string Convert(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
            return string.Empty;

        var doc = new HtmlDocument();
        doc.LoadHtml(html);

        var sb = new StringBuilder();
        ConvertNode(doc.DocumentNode, sb);

        var text = sb.ToString();

        // Clean up excessive whitespace
        text = MultipleNewlines().Replace(text, "\n\n");
        text = MultipleSpaces().Replace(text, " ");
        text = text.Trim();

        return text;
    }

    private static void ConvertNode(HtmlNode node, StringBuilder sb)
    {
        switch (node.NodeType)
        {
            case HtmlNodeType.Text:
                var text = HtmlEntity.DeEntitize(node.InnerText);
                text = text.Trim();
                if (!string.IsNullOrEmpty(text))
                {
                    sb.Append(text);
                    sb.Append(' ');
                }
                break;

            case HtmlNodeType.Element:
                HandleElement(node, sb);
                break;

            case HtmlNodeType.Document:
                foreach (var child in node.ChildNodes)
                    ConvertNode(child, sb);
                break;
        }
    }

    private static void HandleElement(HtmlNode node, StringBuilder sb)
    {
        var tagName = node.Name.ToLowerInvariant();

        // Skip script and style elements
        if (tagName is "script" or "style" or "head")
            return;

        // Handle specific elements
        switch (tagName)
        {
            case "br":
                sb.AppendLine();
                break;

            case "p":
            case "div":
            case "section":
            case "article":
                sb.AppendLine();
                foreach (var child in node.ChildNodes)
                    ConvertNode(child, sb);
                sb.AppendLine();
                break;

            case "h1":
            case "h2":
            case "h3":
            case "h4":
            case "h5":
            case "h6":
                sb.AppendLine();
                sb.AppendLine();
                foreach (var child in node.ChildNodes)
                    ConvertNode(child, sb);
                sb.AppendLine();
                sb.AppendLine();
                break;

            case "li":
                sb.AppendLine();
                sb.Append("  - ");
                foreach (var child in node.ChildNodes)
                    ConvertNode(child, sb);
                break;

            case "a":
                foreach (var child in node.ChildNodes)
                    ConvertNode(child, sb);
                var href = node.GetAttributeValue("href", null);
                if (!string.IsNullOrEmpty(href) && !href.StartsWith('#'))
                {
                    sb.Append(" (");
                    sb.Append(href);
                    sb.Append(')');
                }
                break;

            case "hr":
                sb.AppendLine();
                sb.AppendLine("---");
                sb.AppendLine();
                break;

            case "table":
                sb.AppendLine();
                foreach (var child in node.ChildNodes)
                    ConvertNode(child, sb);
                sb.AppendLine();
                break;

            case "tr":
                foreach (var child in node.ChildNodes)
                    ConvertNode(child, sb);
                sb.AppendLine();
                break;

            case "td":
            case "th":
                foreach (var child in node.ChildNodes)
                    ConvertNode(child, sb);
                sb.Append('\t');
                break;

            default:
                foreach (var child in node.ChildNodes)
                    ConvertNode(child, sb);
                break;
        }
    }

    [GeneratedRegex(@"\n{3,}")]
    private static partial Regex MultipleNewlines();

    [GeneratedRegex(@"[ \t]{2,}")]
    private static partial Regex MultipleSpaces();
}