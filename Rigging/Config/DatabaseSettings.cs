using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public class DatabaseSettings
{
    [Required]
    public string servers { get; set; } = string.Empty;

    [Required]
    public string database { get; set; } = string.Empty;

    [Required]
    public string userId { get; set; } = string.Empty;

    [Required]
    public string password { get; set; } = string.Empty;

    [Required]
    public string lc_collation { get; set; } = string.Empty;
}
