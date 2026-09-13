#include "shortcuts.h"

#include <QHash>

namespace {

struct ShortcutDef {
    const char* id;
    const char* key;
};

const ShortcutDef kDefaults[] = {
    // File
    {"FileOpen", "F3"},
    {"FileAttach", "Alt+A"},
    {"FileDetach", "Ctrl+Alt+F2"},
    {"FileExit", "Alt+X"},
    // View
    {"ViewCpu", "Alt+C"},
    {"ViewLog", "Alt+L"},
    {"ViewNotes", "Alt+N"},
    {"ViewBreakpoints", "Alt+B"},
    {"ViewMemoryMap", "Alt+M"},
    {"ViewCallStack", "Alt+K"},
    {"ViewSEHChain", "Alt+S"},
    {"ViewScript", "Alt+I"},
    {"ViewSymbolInfo", "Alt+E"},
    {"ViewSource", "Alt+Q"},
    {"ViewReferences", "Alt+R"},
    {"ViewThreads", "Alt+T"},
    {"ViewPatches", "Ctrl+P"},
    {"ViewComments", "Ctrl+Alt+C"},
    {"ViewLabels", "Ctrl+Alt+L"},
    {"ViewBookmarks", "Ctrl+Alt+B"},
    {"ViewFunctions", "Ctrl+Alt+F"},
    {"ViewHandles", ""},
    {"ViewGraph", "Alt+G"},
    {"ViewPreviousTab", "Alt+Left"},
    {"ViewNextTab", "Alt+Right"},
    {"ViewPreviousHistory", "Ctrl+Shift+Tab"},
    {"ViewNextHistory", "Ctrl+Tab"},
    {"ViewHideTab", "Ctrl+W"},
    // Debug
    {"DebugRun", "F9"},
    {"DebugeRun", "Shift+F9"},
    {"DebugRunSelection", "F4"},
    {"DebugPause", "F12"},
    {"DebugRestart", "Ctrl+F2"},
    {"DebugClose", "Alt+F2"},
    {"DebugStepInto", "F7"},
    {"DebugeStepInto", "Shift+F7"},
    {"DebugStepIntoSource", "F11"},
    {"DebugStepOver", "F8"},
    {"DebugeStepOver", "Shift+F8"},
    {"DebugStepOverSource", "F10"},
    {"DebugRtr", "Ctrl+F9"},
    {"DebugeRtr", "Ctrl+Shift+F9"},
    {"DebugRtu", "Alt+F9"},
    {"DebugCommand", "Ctrl+Return"},
    {"DebugTraceIntoConditional", "Ctrl+Alt+F7"},
    {"DebugTraceOverConditional", "Ctrl+Alt+F8"},
    {"DebugAnimateInto", "Ctrl+F7"},
    {"DebugAnimateOver", "Ctrl+F8"},
    {"DebugInstrUndo", "Alt+U"},
    // Options / Help
    {"OptionsTopmost", "Ctrl+F5"},
    {"HelpManual", "F1"},
};

} // namespace

QKeySequence shortcutFor(const char* id)
{
    static const QHash<QString, QKeySequence> table = [] {
        QHash<QString, QKeySequence> t;
        for (const auto& d : kDefaults)
            t.insert(QString::fromLatin1(d.id), QKeySequence(QString::fromLatin1(d.key)));
        return t;
    }();
    return table.value(QString::fromLatin1(id));
}
