package socialMedia.service;

import com.google.code.kaptcha.Constants;
import com.google.code.kaptcha.impl.DefaultKaptcha;
import com.google.code.kaptcha.util.Config;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Properties;

@Service
@RequiredArgsConstructor
public class CaptchaService extends DefaultKaptcha{

    public String captchaCode;
    public String generateCaptcha()
    {
        Properties properties = new Properties();
        properties.setProperty(Constants.KAPTCHA_WORDRENDERER_IMPL,"com.google.code.kaptcha.text.impl.DefaultWordRenderer");
        properties.setProperty(Constants.KAPTCHA_OBSCURIFICATOR_IMPL,"com.google.code.kaptcha.impl.WaterRipple");
        properties.setProperty(Constants.KAPTCHA_TEXTPRODUCER_FONT_SIZE,"50");
        properties.setProperty(Constants.KAPTCHA_BORDER_COLOR,"yellow");
        properties.setProperty(Constants.KAPTCHA_BORDER_THICKNESS,"20");
        properties.setProperty(Constants.KAPTCHA_BACKGROUND_IMPL,"com.google.code.kaptcha.impl.DefaultBackground");
        properties.setProperty(Constants.KAPTCHA_BORDER,"yes");
        properties.setProperty(Constants.KAPTCHA_IMAGE_HEIGHT,"100");
        properties.setProperty(Constants.KAPTCHA_IMAGE_WIDTH,"200");
        setConfig(new Config(properties));
        captchaCode=createText();
        return captchaCode;
    }

    public boolean validateCaptcha(String userCaptcha) {
        return captchaCode != null && captchaCode.equals(userCaptcha);
    }

}