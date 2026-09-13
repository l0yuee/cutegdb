#pragma once

#include "cutegdb/src/session.cxxqt.h"

#include <QGraphicsView>
#include <QTableWidget>
#include <QWidget>
#include <cstdint>
#include <functional>

class QLabel;
class QLineEdit;
class QPlainTextEdit;

// Read-only table in the debugger's colours. Each row carries a key (an address, a number...).
class TableView : public QTableWidget {
    Q_OBJECT

public:
    static constexpr std::uint64_t NoKey = UINT64_MAX;

    explicit TableView(const QStringList& headers, QWidget* parent = nullptr);

    // Replaces the rows, keeping the selection on the row with the same key.
    void setRows(const QList<QStringList>& rows, const QList<std::uint64_t>& keys, const QList<bool>& emphasized = {});
    std::uint64_t currentKey() const;
    // Adds a shortcut that is also listed in the context menu; the handler gets the current key.
    void addRowAction(const QKeySequence& key, const QString& text, std::function<void(std::uint64_t)> handler);

signals:
    void rowActivated(std::uint64_t key);
};

class BreakpointsView : public QWidget {
    Q_OBJECT

public:
    explicit BreakpointsView(DebugSession* session, QWidget* parent = nullptr);
    void refresh();

signals:
    void followInDisassembler(std::uint64_t address);

private:
    const BreakpointRow* rowFor(std::uint64_t number) const;

    DebugSession* m_session;
    TableView* m_table;
    rust::Vec<BreakpointRow> m_rows;
};

// Call stack, threads, memory map or handles: a table refreshed whenever the debuggee pauses.
class InfoListView : public QWidget {
    Q_OBJECT

public:
    enum Kind { CallStack, Threads, MemoryMap, Handles };

    InfoListView(Kind kind, DebugSession* session, QWidget* parent = nullptr);
    void refresh();

signals:
    void followInDisassembler(std::uint64_t address);
    void followInDump(std::uint64_t address);

private:
    Kind m_kind;
    DebugSession* m_session;
    TableView* m_table;
};

class SignalsView : public QWidget {
    Q_OBJECT

public:
    explicit SignalsView(DebugSession* session, QWidget* parent = nullptr);
    void refresh();

private:
    DebugSession* m_session;
    TableView* m_table;
    rust::Vec<SignalRow> m_rows;
    bool m_updating = false;
};

// Results of pattern searches, string references and cross references.
class ReferencesView : public QWidget {
    Q_OBJECT

public:
    explicit ReferencesView(DebugSession* session, QWidget* parent = nullptr);
    void refresh();

signals:
    void followInDisassembler(std::uint64_t address);

private:
    DebugSession* m_session;
    class QLabel* m_title;
    TableView* m_table;
};

class TraceView : public QWidget {
    Q_OBJECT

public:
    explicit TraceView(DebugSession* session, QWidget* parent = nullptr);
    void refresh();

signals:
    void followInDisassembler(std::uint64_t address);

private:
    DebugSession* m_session;
    QLabel* m_title;
    TableView* m_table;
};

// Function graph (x64dbg: G): basic blocks laid out in layers, edges coloured by kind.
class GraphView : public QGraphicsView {
    Q_OBJECT

public:
    explicit GraphView(DebugSession* session, QWidget* parent = nullptr);
    void showFunction(std::uint64_t address);
    void rebuild();

signals:
    void followInDisassembler(std::uint64_t address);

protected:
    void mouseDoubleClickEvent(QMouseEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;

private:
    DebugSession* m_session;
    QGraphicsScene* m_scene;
    std::uint64_t m_address = 0;
    bool m_loaded = false;
};

// Script tab: Ctrl+O open and load, Ctrl+R reload, Ctrl+U unload to edit, Space run, Tab step, Esc abort.
class ScriptView : public QWidget {
    Q_OBJECT

public:
    explicit ScriptView(DebugSession* session, QWidget* parent = nullptr);

private:
    bool loadText(const QString& text);
    void setLoaded(bool loaded);
    void highlight(int line, bool running);

    DebugSession* m_session;
    QPlainTextEdit* m_editor;
    QLabel* m_status;
    QString m_path;
    bool m_loaded = false;
};

class SymbolsView : public QWidget {
    Q_OBJECT

public:
    explicit SymbolsView(DebugSession* session, QWidget* parent = nullptr);
    void refreshModules();

signals:
    void followInDisassembler(std::uint64_t address);

private:
    void refreshSymbols();

    DebugSession* m_session;
    TableView* m_modules;
    TableView* m_symbols;
    QLineEdit* m_filter;
    rust::Vec<ModuleRow> m_moduleRows;
};
