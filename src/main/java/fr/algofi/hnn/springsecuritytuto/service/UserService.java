package fr.algofi.hnn.springsecuritytuto.service;

import fr.algofi.hnn.springsecuritytuto.dao.User;
import fr.algofi.hnn.springsecuritytuto.dao.UserRepository;
import fr.algofi.hnn.springsecuritytuto.dto.UserDto;
import fr.algofi.hnn.springsecuritytuto.mapper.CycleAvoidingMappingContext;
import fr.algofi.hnn.springsecuritytuto.mapper.DtoToEntityMapper;
import fr.algofi.hnn.springsecuritytuto.mapper.EntityToDtoMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
@Slf4j
public class UserService {
    private UserRepository userRepository;
    private EntityToDtoMapper toDtoMapper;
    private DtoToEntityMapper toEntityMapper;
    private PasswordEncoder passwordEncoder;

    public List<UserDto> getAllUsers() {
        Iterable<User> ite = userRepository.findAll();
        List<UserDto> result = new ArrayList<>();
        ite.forEach(user -> result.add(toDtoMapper.userToUserDto(user, new CycleAvoidingMappingContext())));
        return result;
    }

    @PostAuthorize("returnObject.get().email == authentication.principal.username || hasRole('ADMIN')")
    public Optional<UserDto> getUserById(Long userId) {
        Optional<User> user = userRepository.findById(userId);
        return user.map(value -> toDtoMapper.userToUserDto(value, new CycleAvoidingMappingContext()));
    }

    @PreAuthorize("hasRole('ADMIN')")
    public Long createUser(UserDto userDto) {
        try {
            User user = toEntityMapper.userDtoToUser(userDto, new CycleAvoidingMappingContext());
            user.setPwd(passwordEncoder.encode(userDto.getPwd()));
            user = userRepository.save(user);
            return user.getId();
        } catch (Exception e) {
            log.error(e.getMessage());
            return null;
        }
    }
}
