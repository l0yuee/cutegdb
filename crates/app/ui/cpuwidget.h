#pragma once

#include <QList>
#include <QWidget>
#include <cstdint>

class DebugSession;
class DisassemblyView;
class DumpView;
class QLabel;
class QPlainTextEdit;
class QTabWidget;
class RegistersView;
class StackView;

// x64dbg's CPU tab: disassembly and info box, registers and arguments, dumps and stack.
class CpuWidget : public QWidget {
    Q_OBJECT

public:
    enum View { Disassembly = 0, Dump = 1, Stack = 2 };

    explicit CpuWidget(DebugSession* session, QWidget* parent = nullptr);

    DisassemblyView* disassembly() const { return m_disassembly; }
    void gotoView(int view, std::uint64_t address);
    void refreshAll();
    // Splitter positions, for restoring the layout between sessions.
    QByteArray saveLayout() const;
    void restoreLayout(const QByteArray& layout);

signals:
    void gotoExpressionRequested(int view);

private:
    void onPaused(std::uint64_t pc);
    void updateInfo(std::uint64_t address);
    void updateArguments();

    DebugSession* m_session;
    DisassemblyView* m_disassembly;
    QPlainTextEdit* m_info;
    RegistersView* m_registers;
    QLabel* m_argumentsHeader;
    QPlainTextEdit* m_arguments;
    QTabWidget* m_dumpTabs;
    QList<DumpView*> m_dumps;
    StackView* m_stack;
    QList<class QSplitter*> m_splitters;
};
