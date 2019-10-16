//package com.jeffrey.example.demospringsecurity.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Profile;
//import org.springframework.session.data.redis.config.ConfigureRedisAction;
//
//@Configuration
//@Profile({"pcf"}) // specify cloud profile so this would only be loaded when deployed to cloud foundry
//public class RedisConfig {
//
//    /**
//     * [ISSUE WORKAROUND]
//     * io.lettuce.core.RedisCommandExecutionException:
//     * ERR Unsupported CONFIG parameter: notify-keyspace-events
//     *
//     * [ROOT CAUSE]
//     * If you are using @EnableRedisHttpSession the SessionMessageListener,
//     * enabling of necessary Redis Keyspace events is done automatically.
//     *
//     * Redis keyspace notifications allows clients to subscribe to Pub/Sub
//     * channels in order to receive events affecting the Redis data set in
//     * some way. This is particularly useful for spring to subscribe to
//     * SessionDestroyedEvent, and is important for WebSocket applications
//     * to ensure open WebSockets are closed when the HttpSession expires.
//     *
//     * However, when running in a secured Redis environment (hosted Redis
//     * services, such as AWS ElastiCache disable this command by default,
//     * with no option to re-enable it.) the config command is disabled.
//     * Since Redis security recommends disabling the CONFIG command so
//     * that remote users cannot reconfigure an instance.
//     *
//     * This means that Spring Session cannot configure Redis Keyspace events
//     * for you. To disable the automatic configuration add ConfigureRedisAction.NO_OP
//     * as a bean.
//     *
//     */
//    @Bean
//    public ConfigureRedisAction configureRedisAction() {
//        // A do nothing implementation of ConfigureRedisAction.
//        return ConfigureRedisAction.NO_OP;
//    }
//
//}
//
