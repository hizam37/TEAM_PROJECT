package socialMedia.exception;



import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;


@ControllerAdvice
public class GlobalAuthenticationExceptionHandler {


    @ExceptionHandler(RegistrationException.class)
    public ResponseEntity<AppError> registrationException(RegistrationException ex) {
        return new ResponseEntity<>(new AppError(HttpStatus.BAD_REQUEST.value(), ex.getMessage()), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(PasswordRecoveryException.class)
    public ResponseEntity<AppError> passwordRecoveryException(PasswordRecoveryException ex) {
        return new ResponseEntity<>(new AppError(HttpStatus.BAD_REQUEST.value(), ex.getMessage()), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(RefreshTokenException.class)
    public ResponseEntity<AppError> refreshTokenExceptionHandler(RefreshTokenException ex) {
        return new ResponseEntity<>(new AppError(HttpStatus.NOT_FOUND.value(), ex.getMessage()), HttpStatus.NOT_FOUND);
    }






}
