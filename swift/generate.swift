#!/usr/bin/env swift
// generate.swift: Generate patterns_gen.swift from YAML pattern definitions
// Usage: swift generate.swift
// Requires: yq (https://github.com/mikefarah/yq)

import Foundation

// MARK: - Utilities

func shell(_ command: String, trimWhitespace: Bool = true) -> (output: String, status: Int32) {
    let task = Process()
    let pipe = Pipe()

    task.standardOutput = pipe
    task.standardError = FileHandle.nullDevice
    task.arguments = ["-c", command]
    task.launchPath = "/bin/bash"
    task.launch()

    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    var output = String(data: data, encoding: .utf8) ?? ""
    task.waitUntilExit()

    if trimWhitespace {
        output = output.trimmingCharacters(in: .whitespacesAndNewlines)
    } else {
        // Only trim trailing newlines, preserve other whitespace
        while output.hasSuffix("\n") || output.hasSuffix("\r") {
            output.removeLast()
        }
    }

    return (output, task.terminationStatus)
}

func yq(_ expression: String, file: String, preserveWhitespace: Bool = false) -> String {
    let (output, status) = shell("yq '\(expression)' '\(file)'", trimWhitespace: !preserveWhitespace)
    if status != 0 {
        fputs("Error: yq failed for expression '\(expression)' on '\(file)'\n", stderr)
        exit(1)
    }
    return output
}

func fileHash(_ path: String) -> String {
    let (output, _) = shell("shasum -a 256 '\(path)' 2>/dev/null | cut -c1-12")
    return output.isEmpty ? "unknown" : output
}

func escapeSwiftString(_ s: String) -> String {
    // Escape backslashes first, then quotes
    var result = s.replacingOccurrences(of: "\\", with: "\\\\")
    result = result.replacingOccurrences(of: "\"", with: "\\\"")
    return result
}

// MARK: - YAML Parsing

struct DirectPattern {
    let pattern: String
    let label: String
    let multiline: Bool
}

struct ContextPattern {
    let prefix: String
    let value: String
    let label: String
}

struct SpecialPattern {
    let name: String
    let pattern: String
    let label: String
    let secretGroup: Int
}

struct PrivateKey {
    let begin: String
    let end: String
}

// MARK: - Main

func main() {
    // Determine script directory
    let scriptPath = CommandLine.arguments[0]
    let scriptDir: String
    if scriptPath.hasPrefix("/") {
        scriptDir = (scriptPath as NSString).deletingLastPathComponent
    } else {
        let cwd = FileManager.default.currentDirectoryPath
        scriptDir = (cwd + "/" + scriptPath as NSString).deletingLastPathComponent
    }

    let patternsDir = (scriptDir as NSString).deletingLastPathComponent + "/patterns"
    let patternsFile = patternsDir + "/patterns.yaml"
    let envFile = patternsDir + "/env.yaml"
    let outputFile = scriptDir + "/patterns_gen.swift"

    // Verify input files exist
    let fm = FileManager.default
    guard fm.fileExists(atPath: patternsFile) else {
        fputs("Error: \(patternsFile) not found\n", stderr)
        exit(1)
    }
    guard fm.fileExists(atPath: envFile) else {
        fputs("Error: \(envFile) not found\n", stderr)
        exit(1)
    }

    // Check yq is available
    let (_, yqStatus) = shell("command -v yq")
    if yqStatus != 0 {
        fputs("Error: yq not found. Install with: brew install yq\n", stderr)
        exit(1)
    }

    // Compute source hashes
    let patternsHash = fileHash(patternsFile)
    let envHash = fileHash(envFile)

    // Get timestamp
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
    let timestamp = formatter.string(from: Date())

    // Parse constants
    let longThreshold = yq(".constants.long_threshold", file: patternsFile)
    let maxPrivateKeyBuffer = yq(".constants.max_private_key_buffer", file: patternsFile)

    // Parse direct patterns
    let patternCount = Int(yq(".patterns | length", file: patternsFile)) ?? 0
    var directPatterns: [DirectPattern] = []

    for i in 0..<patternCount {
        let pattern = yq(".patterns[\(i)].pattern", file: patternsFile)
        let label = yq(".patterns[\(i)].label", file: patternsFile)
        let multilineStr = yq(".patterns[\(i)].multiline // false", file: patternsFile)
        let multiline = multilineStr == "true"

        // Skip multiline patterns (handled by state machine)
        if !multiline {
            directPatterns.append(DirectPattern(pattern: pattern, label: label, multiline: multiline))
        }
    }

    // Parse context patterns
    let contextCount = Int(yq(".context_patterns | length", file: patternsFile)) ?? 0
    var contextPatterns: [ContextPattern] = []

    for i in 0..<contextCount {
        // Preserve whitespace in prefix (e.g., "password " has trailing space)
        let prefix = yq(".context_patterns[\(i)].prefix", file: patternsFile, preserveWhitespace: true)
        let value = yq(".context_patterns[\(i)].value", file: patternsFile)
        let label = yq(".context_patterns[\(i)].label", file: patternsFile)
        contextPatterns.append(ContextPattern(prefix: prefix, value: value, label: label))
    }

    // Parse special patterns
    var specialPatterns: [SpecialPattern] = []

    // git_credential
    let gitCredPattern = yq(".special_patterns.git_credential.pattern", file: patternsFile)
    let gitCredLabel = yq(".special_patterns.git_credential.label", file: patternsFile)
    let gitCredGroup = Int(yq(".special_patterns.git_credential.secret_group", file: patternsFile)) ?? 2
    if gitCredPattern != "null" && !gitCredPattern.isEmpty {
        specialPatterns.append(SpecialPattern(name: "gitCredential", pattern: gitCredPattern, label: gitCredLabel, secretGroup: gitCredGroup))
    }

    // docker_auth
    let dockerAuthPattern = yq(".special_patterns.docker_auth.pattern", file: patternsFile)
    let dockerAuthLabel = yq(".special_patterns.docker_auth.label", file: patternsFile)
    let dockerAuthGroup = Int(yq(".special_patterns.docker_auth.secret_group", file: patternsFile)) ?? 2
    if dockerAuthPattern != "null" && !dockerAuthPattern.isEmpty {
        specialPatterns.append(SpecialPattern(name: "dockerAuth", pattern: dockerAuthPattern, label: dockerAuthLabel, secretGroup: dockerAuthGroup))
    }

    // Parse private key markers
    let privateKeyBegin = yq(".private_key.begin", file: patternsFile)
    let privateKeyEnd = yq(".private_key.end", file: patternsFile)

    // Parse env.yaml
    let explicitCount = Int(yq(".explicit | length", file: envFile)) ?? 0
    var explicitVars: [String] = []
    for i in 0..<explicitCount {
        let name = yq(".explicit[\(i)]", file: envFile)
        explicitVars.append(name)
    }

    let suffixCount = Int(yq(".suffixes | length", file: envFile)) ?? 0
    var envSuffixes: [String] = []
    for i in 0..<suffixCount {
        let suffix = yq(".suffixes[\(i)]", file: envFile)
        envSuffixes.append(suffix)
    }

    // Generate Swift code
    var output = """
    // Code generated by generate.swift - DO NOT EDIT
    // Generated: \(timestamp)
    // Source: patterns/patterns.yaml (hash: \(patternsHash))
    //         patterns/env.yaml (hash: \(envHash))

    import Foundation

    // MARK: - Constants

    let longThreshold = \(longThreshold)
    let maxPrivateKeyBuffer = \(maxPrivateKeyBuffer)

    // MARK: - Direct Patterns
    // Patterns that can be matched without context

    let patterns: [(pattern: String, label: String)] = [

    """

    for (i, p) in directPatterns.enumerated() {
        let comma = i < directPatterns.count - 1 ? "," : ""
        output += "    (\"\(escapeSwiftString(p.pattern))\", \"\(p.label)\")\(comma)\n"
    }

    output += """
    ]

    // MARK: - Context Patterns
    // Patterns that require a prefix context (using capture groups)
    // Format: (pattern, label, secretGroup)
    // The pattern uses capture groups: group 1 = prefix, group 2 = secret value

    let contextPatterns: [(pattern: String, label: String, group: Int)] = [

    """

    for (i, cp) in contextPatterns.enumerated() {
        // Build pattern with capture groups: (prefix)(value)
        let fullPattern = "(\(cp.prefix))(\(cp.value))"
        let comma = i < contextPatterns.count - 1 ? "," : ""
        output += "    (\"\(escapeSwiftString(fullPattern))\", \"\(cp.label)\", 2)\(comma)\n"
    }

    output += """
    ]

    // MARK: - Special Patterns
    // Complex patterns with multiple capture groups

    struct SpecialPattern {
        let pattern: String
        let label: String
        let secretGroup: Int
    }


    """

    for sp in specialPatterns {
        output += """
        let \(sp.name)Pattern = SpecialPattern(
            pattern: \"\(escapeSwiftString(sp.pattern))\",
            label: \"\(sp.label)\",
            secretGroup: \(sp.secretGroup)
        )


        """
    }

    output += """
    // MARK: - Private Key Markers

    let privateKeyBeginPattern = \"\(escapeSwiftString(privateKeyBegin))\"
    let privateKeyEndPattern = \"\(escapeSwiftString(privateKeyEnd))\"

    // MARK: - Environment Variable Detection

    let explicitEnvVars: Set<String> = [

    """

    for (i, v) in explicitVars.enumerated() {
        let comma = i < explicitVars.count - 1 ? "," : ""
        output += "    \"\(v)\"\(comma)\n"
    }

    output += """
    ]

    let envSuffixes: [String] = [

    """

    for (i, s) in envSuffixes.enumerated() {
        let comma = i < envSuffixes.count - 1 ? "," : ""
        output += "    \"\(s)\"\(comma)\n"
    }

    output += """
    ]

    """

    // Write output file
    do {
        try output.write(toFile: outputFile, atomically: true, encoding: .utf8)
        print("Generated: \(outputFile)")
        print("  - \(directPatterns.count) direct patterns")
        print("  - \(contextPatterns.count) context patterns")
        print("  - \(specialPatterns.count) special patterns")
        print("  - \(explicitVars.count) explicit env vars")
        print("  - \(envSuffixes.count) env suffixes")
    } catch {
        fputs("Error writing \(outputFile): \(error)\n", stderr)
        exit(1)
    }
}

main()
