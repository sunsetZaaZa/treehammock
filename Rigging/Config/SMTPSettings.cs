using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public class SMTPSettings
{
    [Required]
    public string SMTPQualifiedDomain { get; set; } = string.Empty;

    [Range(1, 65535)]
    public int SMTPPort { get; set; }

    [Required]
    public string SMTPUsername { get; set; } = string.Empty;

    [Required]
    public string SMTPPassword { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    public string NoReplyEmailAddress { get; set; } = string.Empty;
}
