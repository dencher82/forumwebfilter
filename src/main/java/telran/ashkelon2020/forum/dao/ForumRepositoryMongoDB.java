package telran.ashkelon2020.forum.dao;

import java.time.LocalDate;
import java.util.Set;
import java.util.stream.Stream;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Component;

import telran.ashkelon2020.forum.model.Post;

@Component
public interface ForumRepositoryMongoDB extends MongoRepository<Post, String>{
	
	Stream<Post> findPostsByAuthor(String author);
	
	Stream<Post> findPostsByTagsContaining(Set<String> tags);
	
//	@Query("{'dateCreated':{'$gte':?0,'$lte':?1}}")
	Stream<Post> findByDateCreatedBetween(LocalDate dateFrom, LocalDate dateTo);
	
}
