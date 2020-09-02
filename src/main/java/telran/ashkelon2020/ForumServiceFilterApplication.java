package telran.ashkelon2020;

import java.time.LocalDateTime;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import telran.ashkelon2020.accounting.dao.UserRepositoryMongoDB;
import telran.ashkelon2020.accounting.model.User;

@SpringBootApplication
public class ForumServiceFilterApplication implements CommandLineRunner {
	
	@Autowired
	UserRepositoryMongoDB userRepository;
	
	public static void main(String[] args) {
		SpringApplication.run(ForumServiceFilterApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		if (!userRepository.existsById("admin")) {
			String hashPassword = BCrypt.hashpw("admin", BCrypt.gensalt());
			User admin = new User();
			admin.setLogin("admin");
			admin.setPassword(hashPassword);
			admin.getRoles().add("ADMIN");
			admin.getRoles().add("MODERATOR");
			admin.getRoles().add("USER");
			admin.setExpDate(LocalDateTime.now().plusYears(25));
			admin.setFirstName("Administrator");
			admin.setLastName("Administrator");
			userRepository.save(admin);
		}
		
	}

}
