package telran.ashkelon2020.forum.service;

import java.util.Set;

import telran.ashkelon2020.forum.dto.CommentDto;
import telran.ashkelon2020.forum.dto.DatePeriodDto;
import telran.ashkelon2020.forum.dto.MessageDto;
import telran.ashkelon2020.forum.dto.PostDto;
import telran.ashkelon2020.forum.dto.PostResponseDto;

public interface ForumService {
	
	PostResponseDto addPost(String author, PostDto postDto);
	
	PostResponseDto findPostById(String id);
	
	PostResponseDto deletePost(String id);
	
	PostResponseDto updatePost(String id, PostDto postDto);
	
	boolean addLikeToPost(String id);
	
	PostResponseDto addCommentToPost(String id, String user, MessageDto messageDto);
	
	Iterable<PostResponseDto> findPostsByAuthor(String author);
	
	Iterable<PostResponseDto> findPostsByTags(Set<String> tags);
	
	Iterable<PostResponseDto> findPostsByDates(DatePeriodDto datePeriodDto);
	
	Iterable<CommentDto> findAllPostComments(String id);
	
	Iterable<CommentDto> findAllPostCommentsByAuthor(String id, String author);
	
}
