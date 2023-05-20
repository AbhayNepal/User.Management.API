using System.ComponentModel.DataAnnotations;

namespace User.Management.API.Models.Authentication.Login
{
    public class LoginModel
    {
        [Required(ErrorMessage = "User Name is Required")]
        public string? Username { get; set; }
        [Required(ErrorMessage ="Password is Required")]
        public string? Password { get; set; }

    }
}
