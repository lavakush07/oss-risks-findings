package com.example;

import org.apache.log4j.Logger;
import org.springframework.util.StringUtils;

public class OssRiskDemo {
    private static final Logger log = Logger.getLogger(OssRiskDemo.class);

    public static void main(String[] args) {
        String message = StringUtils.hasText("eol-demo") ? "eol-demo" : "empty";
        log.info("OSS risk demo: " + message);
    }
}
