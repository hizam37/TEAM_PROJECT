package socialMedia.service;



import socialMedia.dto.*;
import socialMedia.exception.PasswordRecoveryException;
import socialMedia.exception.RefreshTokenException;
import socialMedia.exception.RegistrationException;
import socialMedia.model.RefreshToken;
import socialMedia.model.Role;
import socialMedia.model.User;
import socialMedia.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;


@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    private final RefreshTokenService refreshTokenService;

    private final JwtService jwtService;

    private final UserService userService;

    private final CaptchaService captchaService;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;


    public void register(RegistrationDto registrationDto) {

        if (!captchaService.validateCaptcha(registrationDto.getCaptchaSecret())) {
            log.error("Update the captcha!");
            throw new RegistrationException("Update the captcha!");
        }

        User user = User.builder()
                .email(registrationDto.getEmail())
                .firstName(registrationDto.getFirstName())
                .lastName(registrationDto.getLastName())
                .password(passwordEncoder.encode(registrationDto.getPassword1()))
                .deleted(false)
                .roles(List.of(Role.USER)).build();
        userService.create(user);
        if (!registrationDto.getPassword1().equals(registrationDto.getPassword2())) {
            log.error("password did not match!");
            throw new RegistrationException("Passwords do not match");
        }
        registrationDto.setUuid(user.getId());
    }

    public AuthenticateResponseDto login(AuthenticateDto authenticateDto, HttpServletResponse response) {

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticateDto.getEmail(), authenticateDto.getPassword()));
        User user = userService.getByEmail(authenticateDto.getEmail());
        var jwt = jwtService.generateToken(user);
        var refreshToken = refreshTokenService.generateRefreshTokenByUserId(user.getId());
        Cookie cookie = new Cookie("Refresh_token", refreshToken.getToken());
        Cookie cookie2 = new Cookie("Access_token", jwt);
        response.addCookie(cookie);
        response.addCookie(cookie2);
        response.addHeader("Authorization", "Bearer " + jwt);
        return new AuthenticateResponseDto(jwt, refreshToken.getToken());
    }

    public void logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("Refresh_token", "");
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    public User recoverPasswordByEmail(PasswordRecoveryDto recoveryDto) {
        return userService.getByEmail(recoveryDto.getEmail());
    }

    public User recoverPasswordById(UUID id, NewPasswordDto newPasswordDto) {
        Optional<User> user = userService.getById(id);
        if (user.isPresent()) {
            User foundedUser = user.get();
            foundedUser.setPassword(passwordEncoder.encode(newPasswordDto.getPassword()));
            userRepository.save(foundedUser);
            return foundedUser;
        } else {
            throw new PasswordRecoveryException("user by id " + id + " does not exist");
        }
    }

    public AuthenticateResponseDto refreshToken(HttpServletRequest request) {

        Optional<RefreshToken> refreshToken;

        String jwt;

        Cookie[] cookies = request.getCookies();

        for (Cookie cookie : cookies) {

            refreshToken = refreshTokenService.findByRefreshToken(cookie.getValue());

            if (refreshToken.isPresent()) {

                RefreshToken tokenIsActive = refreshTokenService.checkAndUpdateRefreshToken(refreshToken.get());
                Optional<User> user = userRepository.findById(tokenIsActive.getUserId());

                if (user.isPresent()) {
                    var userFound = user.get();
                    jwt = jwtService.generateToken(userFound);

                    return new AuthenticateResponseDto(jwt, tokenIsActive.getToken());
                }
            }
        }
        throw new RefreshTokenException("User is not logged in");
    }
}