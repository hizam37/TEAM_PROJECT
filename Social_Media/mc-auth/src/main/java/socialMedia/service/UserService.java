package socialMedia.service;


import socialMedia.exception.RegistrationException;
import socialMedia.model.User;
import socialMedia.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    private void saveUser(User user) {
        userRepository.save(user);
    }

    public void create(User user) {

        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RegistrationException("This email already exists");
        }

        saveUser(user);
    }

    public User getByEmail(String username) {
        return userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    public Optional<User> getById(UUID id) {
        return userRepository.findById(id);
    }

    public UserDetailsService userDetailsService() {
        return this::getByEmail;
    }

}

