#pragma once

#include <QMainWindow>
#include <cstdint>

class CpuWidget;
class DebugSession;
class QLabel;
class QLineEdit;
class QMenu;
class QPlainTextEdit;
class QTabWidget;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    // Opens and starts debugging `path` (x64dbg: File → Open), once gdb is ready.
    void openExecutable(const QString& path);
    // Runs to the entry breakpoint, saves a screenshot of the CPU tab to `screenshotPath` and exits.
    void runSmokeTest(const QString& screenshotPath);
    // Key sequences bound to more than one action or menu mnemonic, as "key: owner, owner".
    QStringList shortcutConflicts() const;

private:
    void createTabs();
    void createMenus();
    void createPluginsMenu();
    void applyPluginSelection();
    void showPluginStatus();
    void createCommandBar();
    void createStatusBar();
    QAction* addAction(QMenu* menu, const QString& text, const char* shortcutId);
    void showTab(QWidget* tab);
    void setDebugState(int state);
    void appendLog(const QString& text);
    void openFileDialog();
    void askGotoExpression(int view);
    void onGotoRequested(int view, std::uint64_t address);
    void editBreakpoint(std::uint64_t address);
    void assembleAt(std::uint64_t address, const QString& text);
    void editComment(std::uint64_t address);
    void editLabel(std::uint64_t address);
    void editBytes(std::uint64_t address, int size);
    void showPatches();
    // kind: 0 comments, 1 labels, 2 bookmarks.
    void showAnnotations(int kind);
    void findPattern(std::uint64_t address);
    void showAttachDialog();
    void showRemoteDialog();
    void showTraceDialog(bool over);

protected:
    void closeEvent(QCloseEvent* event) override;

private:

    DebugSession* m_session;
    CpuWidget* m_cpu;
    QWidget* m_references;
    class GraphView* m_graph;
    QWidget* m_trace;
    class QComboBox* m_commandType;
    QTabWidget* m_tabs;
    QPlainTextEdit* m_log;
    QLineEdit* m_command;
    QLabel* m_stateLabel;
    QLabel* m_messageLabel;
    QList<class QAction*> m_pluginActions;
    QString m_gdbVersion;
    QString m_pendingExecutable;
};
