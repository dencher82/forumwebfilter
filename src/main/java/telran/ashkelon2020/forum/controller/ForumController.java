package telran.ashkelon2020.forum.controller;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import telran.ashkelon2020.forum.dto.CommentDto;
import telran.ashkelon2020.forum.dto.DatePeriodDto;
import telran.ashkelon2020.forum.dto.MessageDto;
import telran.ashkelon2020.forum.dto.PostDto;
import telran.ashkelon2020.forum.dto.PostResponseDto;
import telran.ashkelon2020.forum.service.ForumService;

@RestController
@RequestMapping("/forum")
public class ForumController {

	@Autowired
	ForumService forumService;

	@PostMapping("/post/{author}")
	public PostResponseDto addPost(@PathVariable String author, @RequestBody PostDto postDto) {
		return forumService.addPost(author, postDto);
	}

	@GetMapping("/post/{id}")
	public PostResponseDto findPostById(@PathVariable String id) {
		return forumService.findPostById(id);
	}

	@DeleteMapping("/post/{id}")
	public PostResponseDto deletePost(@PathVariable String id) {
		return forumService.deletePost(id);
	}

	@PutMapping("/post/{id}")
	public PostResponseDto updatePost(@PathVariable String id, @RequestBody PostDto postDto) {
		return forumService.updatePost(id, postDto);
	}
	
	@PutMapping("/post/{id}/like")
	public boolean addLikeToPost(@PathVariable String id) {
		return forumService.addLikeToPost(id);
	}
	
	@PutMapping("/post/{id}/comment/{author}")
	public PostResponseDto addCommentToPost(@PathVariable String id, @PathVariable("author") String user,
			@RequestBody MessageDto messageDto) {
		return forumService.addCommentToPost(id, user, messageDto);
	}
	
	@GetMapping("/posts/author/{author}")
	public Iterable<PostResponseDto> findPostsByAuthor(@PathVariable String author) {
		return forumService.findPostsByAuthor(author);
	}
	
	@GetMapping("/posts/tags")
	public Iterable<PostResponseDto> findPostsByTags(@RequestBody Set<String> tags) {
		return forumService.findPostsByTags(tags);
	}

	@PostMapping("/posts/date")
	public Iterable<PostResponseDto> findPostsByDates(@RequestBody DatePeriodDto datePeriodDto) { // (@RequestParam(name = "tags") Set<String> tags) {
		return forumService.findPostsByDates(datePeriodDto);
	}

	@GetMapping("/post/{id}/comments")
	public Iterable<CommentDto> findAllPostComments(@PathVariable String id) {
		return forumService.findAllPostComments(id);
	}

	@GetMapping("/post/{id}/comments/{author}/author")
	public Iterable<CommentDto> findAllPostCommentsByAuthor(@PathVariable String id, @PathVariable String author) {
		return forumService.findAllPostCommentsByAuthor(id, author);
	}

}
