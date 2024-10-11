package fr.algofi.hnn.springsecuritytuto.controller;

import fr.algofi.hnn.springsecuritytuto.dto.UserDto;
import fr.algofi.hnn.springsecuritytuto.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Optional;

@RestController
@AllArgsConstructor
public class UserController {

    private UserService service;

    @GetMapping("/users/{userId}")
    public ResponseEntity<UserDto> findById(@PathVariable Long userId) {
        Optional<UserDto> user = service.getUserById(userId);
        return user.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/users")
    public ResponseEntity<UserDto[]> findAllUsers() {
        List<UserDto> users = service.getAllUsers();
        return ResponseEntity.ok(users.toArray(new UserDto[0]));
    }

    @PostMapping("/users")
    public ResponseEntity<Void> createUser(@RequestBody UserDto userDto, UriComponentsBuilder ucb) {
        Long userId = service.createUser(userDto);
        if (userId != null) {
            URI locationOfNewUser = ucb.path("users/{id}").buildAndExpand(userId).toUri();
            return ResponseEntity.created(locationOfNewUser).build();
        } else {
            return ResponseEntity.internalServerError().build();
        }
    }
}
