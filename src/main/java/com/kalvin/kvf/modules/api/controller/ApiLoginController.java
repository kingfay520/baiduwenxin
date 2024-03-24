package com.kalvin.kvf.modules.api.controller;

import com.kalvin.kvf.common.annotation.Log;
import com.kalvin.kvf.common.controller.BaseController;
import com.kalvin.kvf.common.dto.R;
import com.kalvin.kvf.common.utils.HttpServletContextKit;
import com.kalvin.kvf.common.utils.ShiroKit;
import com.wf.captcha.GifCaptcha;
import com.wf.captcha.utils.CaptchaUtil;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("api")
public class ApiLoginController extends BaseController {

    @Value(value = "${kvf.login.authcode.enable}")
    private boolean needAuthCode;

    @Value(value = "${kvf.login.authcode.dynamic}")
    private boolean isDynamic;

    @GetMapping(value = "login")
    public R login() {
        Subject subject = ShiroKit.getSubject();
        if (subject.isAuthenticated()) {
            return R.fail("验证码不正确");
        }
        return R.ok();
    }

    @Log("登录")
    @PostMapping(value = "login")
    public R login(@RequestParam("username") String username, @RequestParam("password") String password, boolean rememberMe) {
        try {
            Subject subject = ShiroKit.getSubject();
            UsernamePasswordToken token = new UsernamePasswordToken(username, password, rememberMe);
            subject.login(token);
            ShiroKit.setSessionAttribute("user", username);
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            return R.fail(e.getMessage());
        }
        return R.ok();
    }

    @Log("退出")
    @GetMapping(value = "logout")
    public R logout() {
        String username = ShiroKit.getUser().getUsername();
        ShiroKit.logout();
        LOGGER.info("{}退出登录", username);
        return R.ok();
    }

    /**
     * 图片验证码
     */
    @GetMapping(value = "captcha")
    public void captcha(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // 可在yml配置kvf.login.authcode.dynamic切换动静态图片验证码，默认静态
        // 其它验证码样式可前往查看：https://gitee.com/whvse/EasyCaptcha
        if (isDynamic) {
            CaptchaUtil.out(new GifCaptcha(), request, response);
        } else {
            CaptchaUtil.out(request, response);
        }
    }
}