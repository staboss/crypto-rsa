package com.staboss.crypto;

import kotlin.io.FilesKt;
import kotlin.text.Charsets;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import java.io.File;

public final class Parser {

    @Option(name = "-g", usage = "generate", forbids = {"-d", "-e", "-s", "-r", "-k"})
    public boolean generate = false;

    @Option(name = "-e", usage = "encrypt message", forbids = {"-d", "-g"})
    public boolean encrypt = false;

    @Option(name = "-d", usage = "decrypt message", forbids = {"-e", "-g"})
    public boolean decrypt = false;

    @Option(name = "-k", usage = "secret key file", metaVar = "KEY")
    public String secretKeyPath;

    @Option(name = "-s", usage = "source file", metaVar = "FILE")
    public String sourceFilePath;

    @Option(name = "-r", usage = "result file", metaVar = "FILE")
    public String resultFilePath;

    public String message;

    private static Parser parser = null;
    private static CmdLineParser cmdLineParser = null;

    private Parser() {
    }

    public static Parser getInstance() {
        if (parser == null) {
            parser = new Parser();
            cmdLineParser = new CmdLineParser(parser);
        }
        return parser;
    }

    public boolean parseArgs(String[] args) {
        try {
            cmdLineParser.parseArgument(args);
            if (!generate) {
                File keyFile = new File(secretKeyPath);
                File messageFile = new File(sourceFilePath);

                if (!keyFile.exists() || !messageFile.exists() || (!encrypt && !decrypt)) {
                    throw new IllegalArgumentException("Check input parameters!");
                }

                message = FilesKt.readText(messageFile, Charsets.UTF_8);
            }
            return true;
        } catch (IllegalArgumentException | CmdLineException e) {
            System.err.println(e.getMessage() + "\n");
            usage();
            return false;
        }
    }

    public static void usage() {
        System.err.println("usage: java -jar crypto-rsa.jar -e|-d -s FILE [-r FILE] -k KEY\n");
        System.err.println(arguments);
    }

    private static final String arguments = "optional arguments:\n" +
            "  -d         : decrypt message\n" +
            "  -e         : encrypt message\n" +
            "  -k KEY     : secret key file\n" +
            "  -s FILE    : source file\n" +
            "  -r FILE    : result file";
}
