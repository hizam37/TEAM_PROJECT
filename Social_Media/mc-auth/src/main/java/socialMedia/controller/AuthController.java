package socialMedia.controller;

import lombok.NonNull;
import socialMedia.dto.*;
import socialMedia.kafka.KafkaProducer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import socialMedia.model.User;
import socialMedia.service.AuthenticationService;
import socialMedia.service.CaptchaService;
import socialMedia.service.JwtService;

import javax.imageio.ImageIO;
import java.io.IOException;
import java.util.UUID;


@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor

public class AuthController {

    private final CaptchaService captchaService;
    String captcha;


    private final KafkaProducer kafkaProducer;


    private final AuthenticationService authenticationService;

    private final JwtService jwtService;


    @PostMapping("/register")
    public void register(@RequestBody @Valid RegistrationDto register) {
        authenticationService.register(register);
        kafkaProducer.sendMessage(register);
    }


    @GetMapping("/check-validation")
    public ResponseEntity<?> checkTokenValidity(@RequestParam String token) {
        log.info("Token received: " + token);
        boolean isTokenValid = jwtService.isTokenValid(token);
        if (!isTokenValid) {
            log.error("Error: token not valid");
        }
        log.info("token isValid: {}", isTokenValid);
        return ResponseEntity.ok(isTokenValid);
    }


    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request) {
        AuthenticateResponseDto authenticateResponseDto = authenticationService.refreshToken(request);
        log.info("authenticateResponseDto " + authenticateResponseDto);
        return ResponseEntity.ok(authenticateResponseDto);
    }


    @PostMapping("/password/recovery")
    public ResponseEntity<?> passwordRecovery(@RequestBody PasswordRecoveryDto passwordRecovery) {
        User user = authenticationService.recoverPasswordByEmail(passwordRecovery);
        log.info("user recovered " + user);
        return ResponseEntity.ok().body(user);
    }


    @PostMapping("/password/recovery/{linkId}")
    public User passwordRecoveryById(@RequestBody NewPasswordDto newPasswordDto, @PathVariable UUID linkId) {
        log.info("password recovered " + newPasswordDto + " for id " + linkId);
        return authenticationService.recoverPasswordById(linkId, newPasswordDto);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid AuthenticateDto authenticateDto, HttpServletResponse response) {
        log.info("logged in " + authenticateDto + " with response " + response);
        AuthenticateResponseDto authenticateResponseDto = authenticationService.login(authenticateDto, response);
        return ResponseEntity.ok(authenticateResponseDto);
    }

    @PostMapping("/logout")
    public void logout(HttpServletResponse response) {
        authenticationService.logout(response);
        log.info("logged out with response " + response);
        ResponseEntity.ok("Successful operation");
    }


    @GetMapping("/captcha")
    public @ResponseBody CaptchaRs captchaActionsHandler() {
        captcha = captchaService.generateCaptcha();
        String uri = "http://79.174.80.200:9095/api/v1/auth/captcha/displayImage";
        return new CaptchaRs(captcha, uri);
    }

    @GetMapping("/captcha/displayImage")
    public void getCaptchaImageHandler(@NonNull HttpServletResponse response) throws IOException {
        response.setContentType("image/jpeg");
        ImageIO.write(captchaService.createImage(captcha),
                "jpeg",
                response.getOutputStream());
        response.flushBuffer();

    }




}
