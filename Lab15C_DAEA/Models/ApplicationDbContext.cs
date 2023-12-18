
using Microsoft.EntityFrameworkCore;
namespace Lab15C_DAEA.Models
{
    public class ApplicationDbContext : DbContext
{
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
       : base(options)
        {
        }
        public DbSet<User> Users { get; set; }

}
}