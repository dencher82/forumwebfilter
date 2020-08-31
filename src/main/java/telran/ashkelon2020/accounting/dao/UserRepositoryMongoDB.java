package telran.ashkelon2020.accounting.dao;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Component;

import telran.ashkelon2020.accounting.model.User;

@Component
public interface UserRepositoryMongoDB extends MongoRepository<User, String> {
	
}
