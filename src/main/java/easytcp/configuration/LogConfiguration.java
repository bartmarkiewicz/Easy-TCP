package easytcp.configuration;


import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.appender.ConsoleAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.builder.api.AppenderComponentBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.core.config.builder.api.RootLoggerComponentBuilder;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;

public class LogConfiguration {

  public static void configureLog4j() {
    //configures Log4J to print logs to the console
    ConfigurationBuilder<BuiltConfiguration> builder = ConfigurationBuilderFactory.newConfigurationBuilder();
    builder.setVerbosity("disable");
    builder.setPackages("easytcp");
    AppenderComponentBuilder appenderBuilder = builder.newAppender("Console", "CONSOLE")
      .addAttribute("target", ConsoleAppender.Target.SYSTEM_OUT);
    // sets the log pattern
    appenderBuilder.add(builder.newLayout("PatternLayout")
      .addAttribute("pattern", "%d %p %c [%t] %m%n"));

    RootLoggerComponentBuilder rootLogger = builder.newRootLogger(Level.ALL);
    rootLogger.add(builder.newAppenderRef("Console"));

    builder.add(appenderBuilder);
    builder.add(rootLogger);
    Configurator.reconfigure(builder.build());
    //logs everything from easytcp
    Configurator.setLevel("easytcp", Level.ALL);
    //omits most pcap4j library logs
    Configurator.setLevel("org.pcap4j", Level.FATAL);
  }
}
