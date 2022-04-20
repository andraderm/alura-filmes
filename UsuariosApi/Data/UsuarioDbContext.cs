using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace UsuariosApi.Data
{
    public class UsuarioDbContext : IdentityDbContext<IdentityUser<int>, IdentityRole<int>, int>
    {
        public UsuarioDbContext(DbContextOptions<UsuarioDbContext> opt) : base(opt)
        {

        }
    }
}
