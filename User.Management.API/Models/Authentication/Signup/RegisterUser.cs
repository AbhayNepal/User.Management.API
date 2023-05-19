using System.ComponentModel.DataAnnotations;

namespace User.Management.API.Models.Authentication.Signup
{
    public class RegisterUser
    {
        [Required(ErrorMessage ="Username is required")]
        public string? Username { get; set; }
        [EmailAddress]
        [Required(ErrorMessage ="Email is Required")]
        public string? Email { get; set; }
        [Required(ErrorMessage ="Password is Required")]
        public string? Password { get; set; }
    }
}
