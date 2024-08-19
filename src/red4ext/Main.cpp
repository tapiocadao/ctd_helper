#include <RED4ext/RED4ext.hpp>
#include <ModSettings/ModSettings.hpp>
#include <RED4ext/Relocation.hpp>
#include <filesystem>
#include <fstream>
#include <libloaderapi.h>
#include <queue>
#include <map>
#include <shellapi.h>
#include <spdlog/spdlog.h>
#include <thread>
#include <winnt.h>
#include <winuser.h>
#include "RED4ext/CNamePool.hpp"
#include "RED4ext/ISerializable.hpp"
#include "RED4ext/InstanceType.hpp"
#include "RED4ext/RTTISystem.hpp"
#include "Utils.hpp"
#include "ScriptHost.hpp"
#include "Addresses.hpp"
#include <Registrar.hpp>
#include "Template.hpp"
#include "Instr.hpp"
#include <CyberpunkMod.hpp>
#include <redscript.h>
#include <string>
#include <windows.h>

#define MAX_CALLS 10

RED4ext::PluginHandle pluginHandle;
bool ctd_helper_enabled = true;

void ctd_helper_callback(RED4ext::CName categoryName, RED4ext::CName propertyName, ModSettings::ModVariableType value) {
    if (propertyName == "enabled") {
        ctd_helper_enabled = value.b;
    }
}

struct BaseFunction {
    uint8_t raw[sizeof(RED4ext::CScriptedFunction)];
};

enum class CallType {
    Unknown,
    Static,
    Method
};

struct FuncCall {
    ~FuncCall() = default;

    BaseFunction func;
    RED4ext::CClass* type;
    std::vector<FuncCall> children;
    FuncCall* parent;
    RED4ext::CClass* contextType;
    RED4ext::IScriptable* context;
    RED4ext::CString contextString;
    uint32_t line;
    CallType callType = CallType::Unknown;

    RED4ext::CBaseFunction * get_func() {
        return reinterpret_cast<RED4ext::CBaseFunction*>(&this->func);
    }

    std::string GetFuncName() {
        std::string fullName(this->get_func()->fullName.ToString());
        if (fullName.find(";") != -1) {
            fullName.replace(fullName.find(";"), 1, "#");
            if (fullName.find(";") != -1) {
                fullName.replace(fullName.find(";"), 1, ") -> ");
                fullName.replace(fullName.find("#"), 1, "(");
            } else {
                fullName.replace(fullName.find("#"), 1, "(");
                fullName.append(")");
            }
        }
        return fullName;
    }
};

struct CallPair {
    ~CallPair() = default;

    FuncCall self;
    FuncCall parent;
    bool isStatic = false;
    RED4ext::WeakHandle<RED4ext::ISerializable> context;
    bool cameBack = false;
    uint16_t line;
};

std::mutex queueLock;
std::map<std::string, std::queue<CallPair>> funcCallQueues;
std::string lastThread;
ScriptBundle * bundle;
bool bundle_loaded = false;

bool scriptLinkingError = false;

wchar_t errorMessage[1000] =
    L"There was an error validating redscript types with their native counterparts. Reference the mod that uses the "
    L"type(s) in the game's message below:\n";
const wchar_t *errorMessageEnd = L"\nYou can press Ctrl+C to copy this message, but it has also been written to the "
                                 L"log at red4ext/logs/ctd_helper.log";
const wchar_t *errorCaption = L"Script Type Validation Error";

// Convert std::wstring to std::string using WideCharToMultiByte
std::string ConvertWStringToString(const std::wstring& wstr) {
    if (wstr.empty()) {
        return std::string();
    }
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
    return str;
}

uintptr_t __fastcall ShowMessageBox(char, char);

REGISTER_HOOK(uintptr_t __fastcall, ShowMessageBox, char a1, char a2) {
    if (scriptLinkingError) {
        swprintf(errorMessage, 1000, L"%s\n%s", errorMessage, errorMessageEnd);
        MessageBoxW(0, errorMessage, errorCaption, MB_SYSTEMMODAL | MB_ICONERROR);
        return 1;
    } else {
        return ShowMessageBox_Original(a1, a2);
    }
}

void __fastcall Breakpoint(RED4ext::IScriptable *context, RED4ext::CStackFrame *stackFrame, uintptr_t a3, uintptr_t a4);

REGISTER_HOOK(void __fastcall, Breakpoint, RED4ext::IScriptable *context, RED4ext::CStackFrame *stackFrame, uintptr_t a3, uintptr_t a4) {
    spdlog::info("Redscript breakpoint encountered");
    __debugbreak();
    Breakpoint_Original(context, stackFrame, a3, a4);
}

int numberOfProcessors = 4;

void LogFunctionCall(RED4ext::IScriptable *context, RED4ext::CStackFrame *stackFrame, RED4ext::CBaseFunction *func, bool isStatic) {

    wchar_t* thread_name;
    HRESULT hr = GetThreadDescription(GetCurrentThread(), &thread_name);
    std::string thread;

    if (SUCCEEDED(hr) && thread_name != nullptr) {
        std::wstring ws(thread_name);
        thread = ConvertWStringToString(ws);
        LocalFree(thread_name);
    }

    #ifdef CTD_HELPER_PROFILING
        RED4ext::CNamePool::Add(thread.c_str());
        auto profiler = CyberpunkMod::Profiler(thread.c_str(), 5);
    #endif

    if (!bundle_loaded) {
        auto bundlePath = Utils::GetRootDir() / "r6" / "cache" / "final.redscripts";
        auto bundleLocation = bundlePath.string();
        spdlog::info("Loading scripts blob: {}", bundleLocation.c_str());
        bundle = bundle_load(bundleLocation.c_str());
        bundle_loaded = true;
    }

    auto invoke = reinterpret_cast<RED4ext::Instr::Invoke *>(stackFrame->code);
    auto call = CallPair();
    call.isStatic = isStatic;
    call.line = invoke->lineNumber;
    call.self.func = *reinterpret_cast<BaseFunction*>(func);
    call.self.type = func->GetParent();
    if (stackFrame->func) {
        call.parent.func = *reinterpret_cast<BaseFunction*>(stackFrame->func);
        call.parent.type = stackFrame->func->GetParent();
    }
    if (context && context->ref.instance == context) {
        call.self.contextType = call.parent.contextType = context->GetType();
    };

    {
        std::lock_guard<std::mutex> lock(queueLock);
        lastThread = thread;
    }
    auto& queue = funcCallQueues[thread];
    queue.emplace(call);
    while (queue.size() > MAX_CALLS) {
        queue.pop();
    }

    #ifdef CTD_HELPER_PROFILING
        auto avg = profiler.End();
        if (avg != 0) {
            spdlog::info("1s of execution in {:<15}: {:7}us", profiler.m_tracker.ToString(), avg);
        }
    #endif
}

void __fastcall InvokeStatic(RED4ext::IScriptable *, RED4ext::CStackFrame *stackFrame, uintptr_t, uintptr_t);

REGISTER_HOOK(void __fastcall, InvokeStatic, RED4ext::IScriptable *context, RED4ext::CStackFrame *stackFrame, uintptr_t a3, uintptr_t a4) {
    if (ctd_helper_enabled) {
        auto invokeStatic = reinterpret_cast<RED4ext::Instr::InvokeStatic *>(stackFrame->code);

        if (invokeStatic->func) {
            LogFunctionCall(context, stackFrame, invokeStatic->func, true);
        }
    }

    InvokeStatic_Original(context, stackFrame, a3, a4);
}

void __fastcall InvokeVirtual(RED4ext::IScriptable *, RED4ext::CStackFrame *stackFrame, uintptr_t a3, uintptr_t a4);

REGISTER_HOOK(void __fastcall, InvokeVirtual, RED4ext::IScriptable *context, RED4ext::CStackFrame *stackFrame, uintptr_t a3, uintptr_t a4) {
    if (ctd_helper_enabled) {
        auto invokeVirtual = reinterpret_cast<RED4ext::Instr::InvokeVirtual *>(stackFrame->code);
        auto cls = context->nativeType;
        if (!cls)
            cls = context->GetNativeType();
        auto func = cls->GetFunction(invokeVirtual->funcName);

        if (func) {
            LogFunctionCall(context, stackFrame, func, false);
        }
    }

    InvokeVirtual_Original(context, stackFrame, a3, a4);
}

std::unordered_map<std::filesystem::path, std::vector<std::string>> files;

void encode_html(std::string& data) {
    std::string buffer;
    buffer.reserve(data.size());
    for (size_t pos = 0; pos != data.size(); ++pos) {
        switch (data[pos]) {
            case '&':  buffer.append("&amp;");       break;
            case '\"': buffer.append("&quot;");      break;
            case '\'': buffer.append("&apos;");      break;
            case '<':  buffer.append("&lt;");        break;
            case '>':  buffer.append("&gt;");        break;
            default:   buffer.append(&data[pos], 1); break;
        }
    }
    data.swap(buffer);
}

#define LINES_BEFORE_TO_PRINT 2
#define LINES_AFTER_TO_PRINT 5

void PrintCall(std::ofstream& htmlLog, FuncCall& call);

void print_redscript_source(std::ofstream& htmlLog, FuncCall& call) {
    if (!call.get_func()->flags.isNative) {
        Decompilation * decomp = nullptr;
        auto funcName = call.get_func()->fullName.ToString();
        if (call.type) {
            decomp = decompile_method(bundle, call.type->GetName().ToString(), funcName);
        } else {
            decomp = decompile_global(bundle, funcName);
        }
        if (!decomp) {
            std::string funcNameStr(funcName);
            if (funcNameStr.find("::") != std::string::npos) {
                auto staticCallName = funcNameStr.substr(0, funcNameStr.find("::"));
                auto staticFuncName = funcNameStr.substr(funcNameStr.find("::") + 2);
                decomp = decompile_method(bundle, staticCallName.c_str(), staticFuncName.c_str());
            }
        }
        if (decomp) {
            auto lineNumbers = decompilation_line_mapping(decomp);
            auto numLines = decompilation_line_count(decomp);
            auto html_id = std::string(funcName);
            while (html_id.find(";") != std::string::npos) {
                html_id.replace(html_id.find(";"), 1, "_");
            }
            htmlLog << fmt::format("<div class='source' id='{}'>", html_id) << std::endl;
            std::string code = decompilation_code(decomp);
            encode_html(code);

            std::stringstream ss(code);
            std::string to;

            uint32_t lineIndex = 0;
            std::vector<uint32_t> usedLines;
            while (std::getline(ss, to, '\n')) {
                if (lineIndex != 0) {
                    bool found = false;
                    bool last = call.children.size() && *lineNumbers == call.children[call.children.size() - 1].line;
                    FuncCall * foundChild = nullptr;
                    for (auto &child : call.children) {
                        if (*lineNumbers == child.line) {
                            found = true;
                            foundChild = &child;
                            break;
                        }
                    }
                    std::string lineNumber;
                    auto firstInstanceOfLineNumber = false;
                    if (std::find(usedLines.begin(), usedLines.end(), *lineNumbers) != usedLines.end()) {
                        lineNumber = fmt::format("{:>5}", "");
                    } else {
                        lineNumber = fmt::format("{:>5}", *lineNumbers);
                        usedLines.push_back(*lineNumbers);
                        firstInstanceOfLineNumber = true;
                    }
                    htmlLog << fmt::format("<pre{}><code class='language-swift indent'>{} {} {}</code></pre>", last ? " class='last-line'" : "", lineNumber, found ? (last ? ">" : "*") : "|", to) << std::endl;
                    if (found && !foundChild->get_func()->flags.isNative && firstInstanceOfLineNumber) {
                        PrintCall(htmlLog, *foundChild);
                    }
                }
                lineNumbers++;
                lineIndex++;
            }
            htmlLog << fmt::format("</div>") << std::endl;
            decompilation_free(decomp);
        } else {
            htmlLog << "<div class='source'><pre><code>(No source found)</code></pre></div>";
        }
    }
}

void print_source(std::ofstream& htmlLog, uint32_t file_idx, uint32_t line_idx, std::string func) {
    auto scriptFile = *ScriptHost::Get()->interface.files.Get(file_idx);
    if (scriptFile) {
        auto path = std::filesystem::path(scriptFile->filename.c_str());
        auto is_red = false;
        if (path.is_relative()) {
            path = Utils::GetRootDir() / "tools" / "redmod" / "scripts" / path;
            is_red = true;
        }
        auto rel_path = std::filesystem::relative(path, Utils::GetRootDir());
        htmlLog << "<div class='source'>" << std::endl;
        if (std::filesystem::exists(path)) {
            if (!files.contains(path)) {
                std::ifstream file(path);
                std::string line;
                while (std::getline(file, line)) {
                    files[path].emplace_back(line);
                }
                file.close();
            }
            if (is_red) {
                for (int idx = 0; idx < files[path].size(); ++idx) {
                    if (files[path][idx].find(func.c_str()) != std::string::npos) {
                        line_idx = idx;
                        break;
                    }
                }
            }
            auto line_index = line_idx;
            htmlLog << fmt::format("<p><a href='{}'>{}:{}</a></p>", path.string().c_str(), rel_path.string().c_str(), line_idx) << std::endl;
            if (files[path].size() > line_index) {
                htmlLog << fmt::format("<pre><code class='language-swift' data-ln-start-from='{}'>", line_idx - LINES_BEFORE_TO_PRINT);
                for (int i = -LINES_BEFORE_TO_PRINT; i <= LINES_AFTER_TO_PRINT; i++) {
                    if (files[path].size() > (line_index + i)) {
                        auto code = files[path][line_index + i];
                        encode_html(code);
                        htmlLog << code << std::endl;
                    }
                }
                htmlLog << fmt::format("</code></pre>") << std::endl;
            } else {
                spdlog::warn("Line number exceded file: {}:{}", path.string().c_str(), line_idx + 1);
            }
        } else {
            htmlLog << fmt::format("<p><a href='{}'>{}:{}</a></p>", path.string().c_str(), rel_path.string().c_str(), line_idx) << std::endl;
            spdlog::warn("Could not locate file: {}", path.string().c_str());
        }
        htmlLog << "</div>" << std::endl;
    }
}

FuncCall * FindFunc(std::vector<FuncCall>& map, RED4ext::CName key) {
    if (auto it = find_if(map.begin(), map.end(), [&key](FuncCall& obj) {
        return obj.get_func()->fullName == key;
    }); it != map.end()) {
        return it._Ptr;
    } else {
        for (auto& value : map) {
            if (auto func = FindFunc(value.children, key); func != nullptr) {
                return func;
            }
        }
        return nullptr;
    }
}

void PrintCall(std::ofstream& htmlLog, FuncCall& call) {
    auto rtti = RED4ext::CRTTISystem::Get();
    htmlLog << "<div class='call'>" << std::endl;
    auto func = call.get_func();
    if (call.contextString.Length()) {
        htmlLog << "<details>\n<summary>";
    }
    htmlLog << fmt::format("<span class='call-name hljs' title='{}'>", call.get_func()->fullName.ToString());
    if (call.callType == CallType::Static) {
        htmlLog << "static ";
    }
    if (call.type) {
        htmlLog << fmt::format("<span class='hljs-type'>{}</span>::", rtti->ConvertNativeToScriptName(call.type->GetName()).ToString());
    }
    htmlLog << fmt::format("<span class='hljs-title'>{}</span>", call.GetFuncName());
    uint32_t line;
    if (call.line) {
        line = call.line;
    } else {
        line = call.get_func()->bytecode.unk04;
    }
    htmlLog << "</span>" << std::endl;
    if (call.contextString.Length()) {
        htmlLog << "</summary>" << std::endl;
        htmlLog << fmt::format("<pre><code>{}</code></pre>", call.contextString.c_str()) << std::endl;
        htmlLog << "</details>" << std::endl;
    }
    print_redscript_source(htmlLog, call);

    auto scriptFile = *ScriptHost::Get()->interface.files.Get(call.get_func()->bytecode.fileIndex);
    if (scriptFile) {
        auto path = std::filesystem::path(scriptFile->filename.c_str());
        htmlLog << fmt::format("<span class='call-name hljs'>{}</span>", path.string().c_str());
    }

    htmlLog << "</div>" << std::endl;
}

std::wstring currentLogFile;

void print_log(std::ofstream& stream, std::string name, std::filesystem::path path) {
    if (std::filesystem::exists(path)) {
        std::ifstream log_file(path);
        std::stringstream log_buffer;
        log_buffer << log_file.rdbuf();
        stream << fmt::format("<details><summary>{} log</summary>\n<div class='source'><pre><code>{}</code></pre></div></details>", name, log_buffer.str()) << std::endl;
    }
}

void __fastcall CrashFunc(uint8_t a1, uintptr_t a2) {
extern void (__fastcall *CrashFunc_Original)(uint8_t, uintptr_t);

    time_t     now = time(0);
    struct tm  tstruct;
    char       log_filename[80];
    char niceTimestamp[80];
    tstruct = *localtime(&now);
    strftime(log_filename, sizeof(log_filename), "%Y-%m-%d_%H-%M-%S.html", &tstruct);
    strftime(niceTimestamp, sizeof(niceTimestamp), "%Y-%m-%d %H:%M:%S", &tstruct);

    auto ctd_helper_dir = Utils::GetRootDir() / "red4ext" / "logs" / "ctd_helper";
    auto currentLogFilePath = ctd_helper_dir / log_filename;
    currentLogFile = currentLogFilePath.wstring();

    spdlog::error(L"Crash! Check {} for details", currentLogFile);

    std::filesystem::create_directories(ctd_helper_dir);

    std::ofstream htmlLog;
    htmlLog.open(currentLogFilePath);
    htmlLog << CTD_HELPER_HEADER;
    htmlLog << fmt::format("<title>CTD Helper Report for Crash on {}</title>\n", niceTimestamp);
    htmlLog << "</head>\n<body>";

    htmlLog << fmt::format("<h1>CTD Helper Report for Crash on {}</h1>\n", niceTimestamp);
    htmlLog << "<p>Generated by <a href='https://github.com/jackhumbert/ctd_helper'>CTD Helper</a>. All code is decompiled redscript from the blob used in the game.</p>\n";

    print_log(htmlLog, "RED4ext", Utils::GetRootDir() / "red4ext" / "logs" / "red4ext.log");
    print_log(htmlLog, "Redscript", Utils::GetRootDir() / "r6" / "logs" / "redscript_rCURRENT.log");
    print_log(htmlLog, "Input Loader", Utils::GetRootDir() / "red4ext" / "logs" / "input_loader.log");

    if (scriptLinkingError) {
        std::wstring werror(errorMessage);
        std::string error(werror.begin(), werror.end());
        htmlLog << fmt::format("<details><summary>Script Linking Error</summary>\n<div class='source'><pre><code>{}</code></pre></div></details>", error);
    }

    std::map<std::string, std::vector<FuncCall>> orgd;

    for (auto &queue : funcCallQueues) {
        auto thread = queue.first;
        for (auto i = 0; queue.second.size(); i++) {
            auto call = queue.second.front();
            call.self.callType = call.isStatic ? CallType::Static : CallType::Method;
            call.self.line = call.line;
            if (orgd[thread].empty()) {
                call.self.callType = call.isStatic ? CallType::Static : CallType::Method;
                auto child = call.parent.children.emplace_back(call.self);
                auto parent = orgd[thread].emplace_back(call.parent);
                child.parent = &parent;
            } else {
                if (auto func = FindFunc(orgd[thread], call.parent.get_func()->fullName); func != nullptr) {
                    auto child = func->children.emplace_back(call.self);
                    child.parent = func;
                } else {
                    auto child = call.parent.children.emplace_back(call.self);
                    auto parent = orgd[thread].emplace_back(call.parent);
                    child.parent = &parent;
                }
            }
            queue.second.pop();
        }
    }

    for (auto &queue : orgd) {
        auto level = 0;
        std::queue<uint64_t> stack;
        auto crashing = lastThread == queue.first;
        htmlLog << fmt::format("<div class='thread'><h2>{0}{1}</h2>", queue.first, crashing ? " LAST EXECUTED":"") << std::endl;
        uint64_t last = 0;
        for (auto& call : queue.second) {
            PrintCall(htmlLog, call);
        }
        htmlLog << "</div>" << std::endl;
    }

    htmlLog << R"(</body>
</html>)";
    htmlLog.close();

    ShellExecute(0, 0, currentLogFile.c_str(), 0, 0 , SW_SHOW );

    bundle_free(bundle);

    auto latest = ctd_helper_dir / "latest.html";
    std::filesystem::copy_file(currentLogFilePath, latest, std::filesystem::copy_options::overwrite_existing);
    spdlog::info("Log copied to {}", latest.string().c_str());

    CrashFunc_Original(a1, a2);
}

__int64 AssertionFailed(const char *, int, const char *, const char *...);

REGISTER_HOOK(__int64, AssertionFailed, const char* file, int lineNum, const char * condition, const char * message...) {
    va_list args;
    va_start(args, message);
    spdlog::error("File: {} @ Line {}", file, lineNum);
    if (condition) {
        spdlog::error("Condition: {}", condition);
    }
    if (message) {
        char buffer[0x400];
        sprintf(buffer, message, args);
        spdlog::error("Message: {}", buffer);
    }
    return AssertionFailed_Original(file, lineNum, condition, message, args);
}

ModSettings::Variable* variable;

RED4EXT_C_EXPORT bool RED4EXT_CALL Main(RED4ext::PluginHandle aHandle, RED4ext::EMainReason aReason, const RED4ext::Sdk *aSdk) {
    switch (aReason) {
    case RED4ext::EMainReason::Load: {
        pluginHandle = aHandle;

        Utils::CreateLogger();
        spdlog::info("Starting up CTD Helper");

        auto ptr = GetModuleHandle(nullptr);
        spdlog::info("Base address: {}", fmt::ptr(ptr));

        ModModuleFactory::GetInstance().Load(aSdk, aHandle);

        numberOfProcessors = std::thread::hardware_concurrency();

        auto handle = GetModuleHandle(L"mod_settings");
        if (!handle) {
            SetDllDirectory((Utils::GetRootDir() / "red4ext" / "plugins" / L"mod_settings").c_str());
            handle = LoadLibrary(L"mod_settings");
        }
        if (handle) {
            typedef void (WINAPI * add_variable_t)(ModSettings::Variable* variable);
            auto addVariable = reinterpret_cast<add_variable_t>(GetProcAddress(handle, "AddVariable"));

            variable = (ModSettings::Variable *)malloc(sizeof(ModSettings::Variable));
            memset(variable, 0, sizeof(ModSettings::Variable));
            variable->modName = "CTD Helper";
            variable->className = "ctd_helper";
            variable->propertyName = "enabled";
            variable->type = "Bool";
            variable->displayName = "Enable Script Function Logging";
            variable->description = "Enable the logging of script calls to aid in diagnosing crashes";
            variable->defaultValue.b = ctd_helper_enabled;
            variable->callback = std::make_shared<ModSettings::runtime_class_callback_t>(ctd_helper_callback);
            addVariable(variable);
        }

        break;
    }
    case RED4ext::EMainReason::Unload: {
        spdlog::info("Shutting down");
        ModModuleFactory::GetInstance().Unload(aSdk, aHandle);
        free(variable);
        spdlog::shutdown();
        break;
    }
    }

    return true;
}

RED4EXT_C_EXPORT void RED4EXT_CALL Query(RED4ext::PluginInfo *aInfo) {
    aInfo->name = L"CTD Helper";
    aInfo->author = L"Jack Humbert";
    auto version = RED4ext::v0::CreateSemVer(1, 0, 0, RED4EXT_V0_SEMVER_PRERELEASE_TYPE_NONE, 0);
    aInfo->runtime = RED4EXT_RUNTIME_LATEST;
    aInfo->sdk = RED4EXT_SDK_LATEST;
}

RED4EXT_C_EXPORT uint32_t RED4EXT_CALL Supports() { return RED4EXT_API_VERSION_LATEST; }
