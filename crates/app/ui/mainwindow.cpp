#include "mainwindow.h"
#include "cpuwidget.h"
#include "disassemblyview.h"
#include "shortcuts.h"
#include "theme.h"
#include "views.h"

#include "cutegdb/src/session.cxxqt.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QCloseEvent>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QVBoxLayout>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontDatabase>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMap>
#include <QMenu>
#include <QMenuBar>
#include <QPlainTextEdit>
#include <QStatusBar>
#include <QTabWidget>
#include <QTimer>
#include <QToolBar>
#include <cstdio>
#include <functional>
#include <memory>

namespace {

enum DebugState { Terminated = 0, Paused = 1, Running = 2 };

// Lets UI tests confirm that an action or dialog was confirmed.
void traceAction(const char* name)
{
    static const bool trace = qEnvironmentVariableIsSet("CUTEGDB_UI_LOG");
    if (trace) {
        std::printf("[action] %s\n", name);
        std::fflush(stdout);
    }
}

QWidget* placeholderTab(const QString& name)
{
    auto* w = new QWidget;
    w->setObjectName(name);
    return w;
}

} // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , m_session(new DebugSession(this))
{
    setWindowTitle(QStringLiteral("cutegdb"));
    resize(1280, 800);

    createTabs();
    createMenus();
    createCommandBar();
    createStatusBar();

    connect(m_session, &DebugSession::logMessage, this, &MainWindow::appendLog);
    connect(m_session, &DebugSession::stateChanged, this, &MainWindow::setDebugState);
    connect(m_session, &DebugSession::gdbReady, this, [this](QString version) { m_gdbVersion = version; });
    connect(m_session, &DebugSession::paused, this, [this](std::uint64_t) { showTab(m_cpu); });
    connect(m_session, &DebugSession::gotoRequested, this, &MainWindow::onGotoRequested);
    connect(m_session, &DebugSession::clearLogRequested, m_log, &QPlainTextEdit::clear);
    connect(m_cpu, &CpuWidget::gotoExpressionRequested, this, &MainWindow::askGotoExpression);

    QSettings settings;
    restoreGeometry(settings.value(QStringLiteral("window/geometry")).toByteArray());
    restoreState(settings.value(QStringLiteral("window/state")).toByteArray());
    m_cpu->restoreLayout(settings.value(QStringLiteral("cpu/layout")).toByteArray());

    setDebugState(Terminated);
    m_session->start();
}

MainWindow::~MainWindow() = default;

void MainWindow::createTabs()
{
    m_tabs = new QTabWidget;
    m_tabs->setMovable(true);
    m_tabs->setDocumentMode(true);

    m_cpu = new CpuWidget(m_session);
    m_cpu->setObjectName(QStringLiteral("CPU"));

    m_log = new QPlainTextEdit;
    m_log->setObjectName(QStringLiteral("Log"));
    m_log->setReadOnly(true);
    m_log->setFont(theme::monospaceFont());
    m_log->setMaximumBlockCount(100000);

    // Same order as x64dbg's main tab bar.
    m_tabs->addTab(m_cpu, tr("CPU"));
    m_tabs->addTab(m_log, tr("Log"));
    m_tabs->addTab(placeholderTab(QStringLiteral("Notes")), tr("Notes"));
    const auto named = [](QWidget* widget, const char* name) {
        widget->setObjectName(QString::fromLatin1(name));
        return widget;
    };
    auto* breakpoints = new BreakpointsView(m_session);
    auto* memoryMap = new InfoListView(InfoListView::MemoryMap, m_session);
    auto* callStack = new InfoListView(InfoListView::CallStack, m_session);
    auto* signalsView = new SignalsView(m_session);
    auto* symbols = new SymbolsView(m_session);
    auto* threads = new InfoListView(InfoListView::Threads, m_session);
    auto* handles = new InfoListView(InfoListView::Handles, m_session);

    m_tabs->addTab(named(breakpoints, "Breakpoints"), tr("Breakpoints"));
    m_tabs->addTab(named(memoryMap, "MemoryMap"), tr("Memory Map"));
    m_tabs->addTab(named(callStack, "CallStack"), tr("Call Stack"));
    m_tabs->addTab(named(signalsView, "Signals"), tr("Signals"));
    auto* script = new ScriptView(m_session);
    m_tabs->addTab(named(script, "Script"), tr("Script"));
    m_tabs->addTab(named(symbols, "Symbols"), tr("Symbols"));
    m_tabs->addTab(placeholderTab(QStringLiteral("Source")), tr("Source"));
    auto* references = new ReferencesView(m_session);
    m_references = named(references, "References");
    m_tabs->addTab(m_references, tr("References"));
    m_tabs->addTab(named(threads, "Threads"), tr("Threads"));
    m_tabs->addTab(named(handles, "Handles"), tr("Handles"));

    const auto toDisassembly = [this](std::uint64_t address) { onGotoRequested(CpuWidget::Disassembly, address); };
    const auto toDump = [this](std::uint64_t address) { onGotoRequested(CpuWidget::Dump, address); };
    connect(breakpoints, &BreakpointsView::followInDisassembler, this, toDisassembly);
    connect(callStack, &InfoListView::followInDisassembler, this, toDisassembly);
    connect(memoryMap, &InfoListView::followInDump, this, toDump);
    connect(symbols, &SymbolsView::followInDisassembler, this, toDisassembly);
    connect(m_cpu->disassembly(), &DisassemblyView::editBreakpointRequested, this, &MainWindow::editBreakpoint);
    connect(m_cpu->disassembly(), &DisassemblyView::assembleRequested, this, &MainWindow::assembleAt);
    connect(m_cpu->disassembly(), &DisassemblyView::commentRequested, this, &MainWindow::editComment);
    connect(m_cpu->disassembly(), &DisassemblyView::labelRequested, this, &MainWindow::editLabel);
    connect(m_cpu->disassembly(), &DisassemblyView::binaryEditRequested, this, &MainWindow::editBytes);
    connect(m_cpu->disassembly(), &DisassemblyView::searchPatternRequested, this, &MainWindow::findPattern);
    connect(m_cpu->disassembly(), &DisassemblyView::stringReferencesRequested, this, [this](std::uint64_t address) {
        traceAction("String references");
        m_session->findStringReferences(address);
    });
    connect(m_cpu->disassembly(), &DisassemblyView::referencesRequested, this, [this](std::uint64_t address) {
        traceAction("References");
        m_session->findReferencesTo(address);
    });
    connect(references, &ReferencesView::followInDisassembler, this, toDisassembly);
    connect(m_cpu->disassembly(), &DisassemblyView::graphRequested, this, [this](std::uint64_t address) {
        traceAction("Graph");
        showTab(m_graph);
        m_graph->showFunction(address);
    });
    connect(m_session, &DebugSession::referencesChanged, this, [this](QString) { showTab(m_references); });
    auto* trace = new TraceView(m_session);
    m_trace = trace;
    trace->setObjectName(QStringLiteral("Trace"));
    m_tabs->addTab(trace, tr("Trace"));
    m_graph = new GraphView(m_session);
    m_graph->setObjectName(QStringLiteral("Graph"));
    m_tabs->addTab(m_graph, tr("Graph"));
    connect(trace, &TraceView::followInDisassembler, this, [this](std::uint64_t address) {
        onGotoRequested(CpuWidget::Disassembly, address);
    });
    connect(m_graph, &GraphView::followInDisassembler, this, [this](std::uint64_t address) {
        onGotoRequested(CpuWidget::Disassembly, address);
    });
    connect(m_session, &DebugSession::traceChanged, this, [this] { showTab(m_trace); });
    setCentralWidget(m_tabs);
}

QAction* MainWindow::addAction(QMenu* menu, const QString& text, const char* shortcutId)
{
    QAction* action = menu->addAction(text);
    if (shortcutId) {
        action->setShortcut(shortcutFor(shortcutId));
        action->setShortcutContext(Qt::ApplicationShortcut);
    }
    return action;
}

void MainWindow::showTab(QWidget* tab)
{
    m_tabs->setCurrentWidget(tab);
}

void MainWindow::createMenus()
{
    QMenu* file = menuBar()->addMenu(tr("&File"));
    connect(addAction(file, tr("&Open"), "FileOpen"), &QAction::triggered, this, &MainWindow::openFileDialog);
    connect(addAction(file, tr("&Attach"), "FileAttach"), &QAction::triggered, this, &MainWindow::showAttachDialog);
    connect(addAction(file, tr("&Detach"), "FileDetach"), &QAction::triggered, this, [this] {
        traceAction("Detach");
        m_session->detach();
    });
    connect(addAction(file, tr("Connect to &remote target..."), nullptr), &QAction::triggered, this,
        &MainWindow::showRemoteDialog);
    file->addSeparator();
    connect(addAction(file, tr("E&xit"), "FileExit"), &QAction::triggered, this, &QWidget::close);

    QMenu* view = menuBar()->addMenu(tr("&View"));
    const struct {
        const char* name;
        QString text;
        const char* shortcut;
    } views[] = {
        {"CPU", tr("&CPU"), "ViewCpu"},
        {"Log", tr("&Log"), "ViewLog"},
        {"Notes", tr("&Notes"), "ViewNotes"},
        {"Breakpoints", tr("&Breakpoints"), "ViewBreakpoints"},
        {"MemoryMap", tr("&Memory Map"), "ViewMemoryMap"},
        {"CallStack", tr("Call Stac&k"), "ViewCallStack"},
        {"Signals", tr("&Signals"), "ViewSEHChain"},
        {"Script", tr("Scr&ipt"), "ViewScript"},
        {"Symbols", tr("Symbol &Info"), "ViewSymbolInfo"},
        {"Source", tr("Source"), "ViewSource"},
        {"References", tr("&References"), "ViewReferences"},
        {"Threads", tr("&Threads"), "ViewThreads"},
        {"Handles", tr("&Handles"), "ViewHandles"},
        {"Trace", tr("Trace"), nullptr},
        {"Graph", tr("&Graph"), "ViewGraph"},
    };
    for (const auto& v : views) {
        QWidget* tab = m_tabs->findChild<QWidget*>(QString::fromLatin1(v.name));
        connect(addAction(view, v.text, v.shortcut), &QAction::triggered, this, [this, tab] {
            showTab(tab);
            tab->setFocus();
        });
    }
    view->addSeparator();
    connect(addAction(view, tr("&Patches"), "ViewPatches"), &QAction::triggered, this, &MainWindow::showPatches);
    connect(addAction(view, tr("Comments"), "ViewComments"), &QAction::triggered, this, [this] { showAnnotations(0); });
    connect(addAction(view, tr("Labels"), "ViewLabels"), &QAction::triggered, this, [this] { showAnnotations(1); });
    connect(addAction(view, tr("Bookmarks"), "ViewBookmarks"), &QAction::triggered, this, [this] { showAnnotations(2); });
    view->addSeparator();
    connect(addAction(view, tr("Previous Tab"), "ViewPreviousTab"), &QAction::triggered, this, [this] {
        m_tabs->setCurrentIndex((m_tabs->currentIndex() + m_tabs->count() - 1) % m_tabs->count());
    });
    connect(addAction(view, tr("Next Tab"), "ViewNextTab"), &QAction::triggered, this, [this] {
        m_tabs->setCurrentIndex((m_tabs->currentIndex() + 1) % m_tabs->count());
    });

    QMenu* debug = menuBar()->addMenu(tr("&Debug"));
    const struct {
        QString text;
        const char* shortcut;
        std::function<void()> handler;
    } debugItems[] = {
        {tr("&Run"), "DebugRun", [this] { m_session->run(); }},
        {tr("&Pause"), "DebugPause", [this] { m_session->pause(); }},
        {tr("Re&start"), "DebugRestart", [this] { m_session->restart(); }},
        {tr("&Close"), "DebugClose", [this] { m_session->stop(); }},
        {tr("Step &into"), "DebugStepInto", [this] { m_session->stepInto(); }},
        {tr("Step &over"), "DebugStepOver", [this] { m_session->stepOver(); }},
        {tr("Run to &selection"), "DebugRunSelection",
            [this] { m_session->runToAddress(m_cpu->disassembly()->selectedAddress()); }},
        {tr("Execute till return"), "DebugRtr", [this] { m_session->executeTillReturn(); }},
        {tr("Run to user code"), "DebugRtu", [this] { m_session->runToUserCode(); }},
        {tr("Command"), "DebugCommand", [this] {
             m_command->setFocus();
             m_command->selectAll();
         }},
    };
    for (const auto& item : debugItems) {
        QAction* action = addAction(debug, item.text, item.shortcut);
        const QString name = QString(item.text).remove(QLatin1Char('&'));
        connect(action, &QAction::triggered, this, [name, handler = item.handler] {
            // Lets UI tests confirm which action a key press triggered.
            static const bool trace = qEnvironmentVariableIsSet("CUTEGDB_UI_LOG");
            if (trace) {
                std::printf("[action] %s\n", qPrintable(name));
                std::fflush(stdout);
            }
            handler();
        });
    }

    // No mnemonics where Alt+<letter> is already a view shortcut (Alt+T threads, Alt+I script, ...).
    QMenu* tracing = menuBar()->addMenu(tr("Tracing"));
    connect(addAction(tracing, tr("Trace &into..."), "DebugTraceIntoConditional"), &QAction::triggered, this,
        [this] { showTraceDialog(false); });
    connect(addAction(tracing, tr("Trace &over..."), "DebugTraceOverConditional"), &QAction::triggered, this,
        [this] { showTraceDialog(true); });
    createPluginsMenu();
    menuBar()->addMenu(tr("Favourites"));
    menuBar()->addMenu(tr("&Options"));
    menuBar()->addMenu(tr("&Help"));
}

void MainWindow::createPluginsMenu()
{
    QMenu* menu = menuBar()->addMenu(tr("&Plugins"));
    const QStringList enabled = QSettings().value(QStringLiteral("plugins/enabled")).toStringList();

    QMenu* categories[2] = {menu->addMenu(tr("Anti-anti-&debug")), menu->addMenu(tr("Anti-anti-&VM"))};
    for (const PluginRow& row : m_session->pluginCatalog()) {
        QMenu* parent = categories[row.category == 1 ? 1 : 0];
        QString label = qs(row.name);
        if (row.best_effort)
            label += tr(" (best-effort)");
        QAction* action = parent->addAction(label);
        action->setCheckable(true);
        action->setChecked(enabled.contains(qs(row.id)));
        action->setToolTip(qs(row.description));
        action->setData(qs(row.id));
        connect(action, &QAction::toggled, this, [this] { applyPluginSelection(); });
        m_pluginActions << action;
    }
    for (QMenu* category : categories) {
        category->setToolTipsVisible(true);
        category->addSeparator();
        connect(category->addAction(tr("Enable all")), &QAction::triggered, this, [category] {
            for (QAction* a : category->actions())
                if (a->isCheckable())
                    a->setChecked(true);
        });
        connect(category->addAction(tr("Disable all")), &QAction::triggered, this, [category] {
            for (QAction* a : category->actions())
                if (a->isCheckable())
                    a->setChecked(false);
        });
    }
    menu->addSeparator();
    connect(menu->addAction(tr("Plugin &status...")), &QAction::triggered, this, &MainWindow::showPluginStatus);

    // Hand the restored selection to the core so it is auto-applied when a target starts.
    applyPluginSelection();
}

void MainWindow::applyPluginSelection()
{
    QStringList ids;
    for (QAction* action : m_pluginActions)
        if (action->isChecked())
            ids << action->data().toString();
    QSettings().setValue(QStringLiteral("plugins/enabled"), ids);
    traceAction("Plugins");
    m_session->setEnabledPlugins(ids.join(QLatin1Char(',')));
}

void MainWindow::showPluginStatus()
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Plugin status"));
    auto* table = new TableView({tr("Countermeasure"), tr("Checks neutralized")});
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(new QLabel(tr("Active countermeasures and how many checks each has neutralized:")));
    layout->addWidget(table);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    auto refresh = [this, table] {
        QList<QStringList> rows;
        for (const PluginStatRow& row : m_session->pluginStatRows())
            rows << QStringList{qs(row.name), QString::number(row.count)};
        if (rows.isEmpty())
            rows << QStringList{tr("(no countermeasures active)"), QString()};
        table->setRows(rows, QList<std::uint64_t>{});
    };
    connect(m_session, &DebugSession::pluginStatsChanged, &dialog, refresh);
    m_session->refreshPluginStats();
    refresh();
    dialog.resize(440, 320);
    dialog.exec();
}

void MainWindow::createCommandBar()
{
    auto* bar = new QToolBar(tr("Command"));
    bar->setObjectName(QStringLiteral("CommandBar"));
    bar->setMovable(false);
    bar->addWidget(new QLabel(tr("Command: ")));
    m_command = new QLineEdit;
    m_command->setObjectName(QStringLiteral("CommandLine"));
    bar->addWidget(m_command);
    m_commandType = new QComboBox;
    m_commandType->addItems({tr("Default"), tr("Python")});
    bar->addWidget(m_commandType);
    addToolBar(Qt::BottomToolBarArea, bar);

    connect(m_command, &QLineEdit::returnPressed, this, [this] {
        const QString text = m_command->text();
        if (text.trimmed().isEmpty())
            return;
        if (m_commandType->currentIndex() == 1)
            m_session->executePython(text);
        else
            m_session->executeCommand(text);
        m_command->clear();
    });
}

void MainWindow::createStatusBar()
{
    m_stateLabel = new QLabel;
    m_stateLabel->setObjectName(QStringLiteral("StateLabel"));
    m_stateLabel->setAlignment(Qt::AlignCenter);
    m_stateLabel->setMinimumWidth(90);
    m_messageLabel = new QLabel;
    statusBar()->addWidget(m_stateLabel);
    statusBar()->addWidget(m_messageLabel, 1);
}

void MainWindow::setDebugState(int state)
{
    QString text;
    QString color;
    switch (state) {
    case Paused:
        text = tr("Paused");
        color = QStringLiteral("#ffff00");
        break;
    case Running:
        text = tr("Running");
        color = QStringLiteral("#00ff00");
        break;
    default:
        text = tr("Terminated");
        color = QStringLiteral("#c0c0c0");
        break;
    }
    m_stateLabel->setText(text);
    m_stateLabel->setStyleSheet(QStringLiteral("QLabel { background-color: %1; color: black; padding: 0 6px; }").arg(color));
}

void MainWindow::appendLog(const QString& text)
{
    static const bool echo = qEnvironmentVariableIsSet("CUTEGDB_UI_LOG");
    if (echo) {
        std::printf("%s\n", qPrintable(text));
        std::fflush(stdout);
    }
    m_log->appendPlainText(text);
    const QString last = text.section(QLatin1Char('\n'), -1).trimmed();
    if (!last.isEmpty())
        m_messageLabel->setText(last);
}

void MainWindow::openFileDialog()
{
    const QString path = QFileDialog::getOpenFileName(this, tr("Open File"));
    if (!path.isEmpty())
        openExecutable(path);
}

void MainWindow::openExecutable(const QString& path)
{
    const QString absolute = QFileInfo(path).absoluteFilePath();
    m_pendingExecutable = absolute;
    auto load = [this, absolute] {
        setWindowTitle(QStringLiteral("cutegdb - %1").arg(QFileInfo(absolute).fileName()));
        m_session->openExecutable(absolute, QString());
    };
    if (m_gdbVersion.isEmpty())
        connect(m_session, &DebugSession::gdbReady, this, load, Qt::SingleShotConnection);
    else
        load();
}

void MainWindow::askGotoExpression(int view)
{
    static const char* titles[] = {
        QT_TR_NOOP("Enter expression to follow in Disassembler..."),
        QT_TR_NOOP("Enter expression to follow in Dump..."),
        QT_TR_NOOP("Enter expression to follow in Stack..."),
    };
    bool ok = false;
    const QString expression = QInputDialog::getText(this, tr(titles[qBound(0, view, 2)]), tr("Expression:"),
        QLineEdit::Normal, QString(), &ok);
    if (ok && !expression.trimmed().isEmpty())
        m_session->evaluateGoto(view, expression);
}

void MainWindow::onGotoRequested(int view, std::uint64_t address)
{
    showTab(m_cpu);
    m_cpu->gotoView(view, address);
}

void MainWindow::showTraceDialog(bool over)
{
    QDialog dialog(this);
    dialog.setWindowTitle(over ? tr("Trace over") : tr("Trace into"));
    auto* condition = new QLineEdit;
    condition->setFont(theme::monospaceFont());
    condition->setPlaceholderText(tr("Break condition, e.g. cip==hello.main or byte:[cip]==C3"));
    condition->setMinimumWidth(420);
    auto* maxSteps = new QSpinBox;
    maxSteps->setRange(1, 10000000);
    maxSteps->setValue(50000);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(new QLabel(tr("Break condition:")));
    layout->addWidget(condition);
    layout->addWidget(new QLabel(tr("Maximum trace count:")));
    layout->addWidget(maxSteps);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    if (dialog.exec() != QDialog::Accepted)
        return;
    traceAction(over ? "Trace over" : "Trace into");
    m_session->trace(over, condition->text(), maxSteps->value());
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    QSettings settings;
    settings.setValue(QStringLiteral("window/geometry"), saveGeometry());
    settings.setValue(QStringLiteral("window/state"), saveState());
    settings.setValue(QStringLiteral("cpu/layout"), m_cpu->saveLayout());
    QMainWindow::closeEvent(event);
}

void MainWindow::showAttachDialog()
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Attach"));
    dialog.resize(760, 480);
    auto* filter = new QLineEdit;
    filter->setPlaceholderText(tr("Filter by PID, name or path"));
    auto* table = new TableView({tr("PID"), tr("Name"), tr("Path")});
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel);
    auto* attachButton = buttons->addButton(tr("&Attach"), QDialogButtonBox::AcceptRole);
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(filter);
    layout->addWidget(table);
    layout->addWidget(buttons);

    const auto refresh = [this, table, filter] {
        const QString text = filter->text().trimmed();
        QList<QStringList> rows;
        QList<std::uint64_t> keys;
        for (const ProcessRow& row : m_session->processRows()) {
            const QStringList cells{QString::number(row.pid), qs(row.name), qs(row.path)};
            if (!text.isEmpty() && !cells.join(QLatin1Char(' ')).contains(text, Qt::CaseInsensitive))
                continue;
            rows << cells;
            keys << row.pid;
        }
        table->setRows(rows, keys);
    };
    refresh();
    connect(filter, &QLineEdit::textChanged, &dialog, refresh);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(attachButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    connect(table, &TableView::rowActivated, &dialog, &QDialog::accept);
    if (dialog.exec() != QDialog::Accepted || table->currentKey() == TableView::NoKey)
        return;
    traceAction("Attach");
    const auto pid = std::uint32_t(table->currentKey());
    setWindowTitle(QStringLiteral("cutegdb - %1").arg(table->item(table->currentRow(), 1)->text()));
    m_session->attach(pid);
}

void MainWindow::showRemoteDialog()
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Connect to remote target"));
    auto* address = new QLineEdit(QStringLiteral("localhost:1234"));
    auto* executable = new QLineEdit;
    executable->setPlaceholderText(tr("Executable with symbols (optional)"));
    auto* browse = new QPushButton(tr("&Browse..."));
    auto* executableRow = new QHBoxLayout;
    executableRow->addWidget(executable);
    executableRow->addWidget(browse);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(new QLabel(tr("gdbserver or gdb stub (host:port):")));
    layout->addWidget(address);
    layout->addLayout(executableRow);
    layout->addWidget(buttons);
    connect(browse, &QPushButton::clicked, &dialog, [&dialog, executable] {
        const QString path = QFileDialog::getOpenFileName(&dialog, tr("Executable"));
        if (!path.isEmpty())
            executable->setText(path);
    });
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    if (dialog.exec() != QDialog::Accepted || address->text().trimmed().isEmpty())
        return;
    traceAction("Connect remote");
    if (!executable->text().trimmed().isEmpty())
        setWindowTitle(QStringLiteral("cutegdb - %1").arg(QFileInfo(executable->text().trimmed()).fileName()));
    m_session->connectRemote(address->text(), executable->text());
}

void MainWindow::findPattern(std::uint64_t address)
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Find Pattern..."));
    auto* pattern = new QLineEdit;
    pattern->setFont(theme::monospaceFont());
    pattern->setPlaceholderText(tr("Hex bytes, ? for wildcards: 48 8B ?? 05"));
    pattern->setMinimumWidth(420);
    auto* scope = new QComboBox;
    scope->addItems({tr("Current module"), tr("Entire memory")});
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(pattern);
    layout->addWidget(scope);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    if (dialog.exec() != QDialog::Accepted || pattern->text().trimmed().isEmpty())
        return;
    traceAction("Find pattern");
    m_session->searchPattern(address, pattern->text(), scope->currentIndex() == 1);
}

void MainWindow::assembleAt(std::uint64_t address, const QString& text)
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Assemble at %1").arg(m_session->formatAddress(address)));
    auto* edit = new QLineEdit(text);
    edit->setFont(theme::monospaceFont());
    edit->setMinimumWidth(480);
    edit->selectAll();
    auto* fill = new QCheckBox(tr("Fill with NOP's"));
    fill->setChecked(true);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(edit);
    layout->addWidget(fill);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    if (dialog.exec() != QDialog::Accepted || edit->text().trimmed().isEmpty())
        return;
    traceAction("Assemble");
    m_session->assemble(address, edit->text(), fill->isChecked());
}

void MainWindow::editComment(std::uint64_t address)
{
    bool ok = false;
    const QString text = QInputDialog::getText(this, tr("Add comment at %1").arg(m_session->formatAddress(address)),
        tr("Comment:"), QLineEdit::Normal, m_session->commentAt(address), &ok);
    if (!ok)
        return;
    traceAction("Comment");
    m_session->setComment(address, text);
}

void MainWindow::editLabel(std::uint64_t address)
{
    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("Add label at %1").arg(m_session->formatAddress(address)),
        tr("Label:"), QLineEdit::Normal, m_session->labelAt(address), &ok);
    if (!ok)
        return;
    traceAction("Label");
    m_session->setLabel(address, name);
}

void MainWindow::editBytes(std::uint64_t address, int size)
{
    QStringList current;
    for (const std::int16_t byte : m_session->readMemory(address, qMax(size, 1)))
        current << (byte < 0 ? QStringLiteral("??") : QStringLiteral("%1").arg(byte, 2, 16, QLatin1Char('0')).toUpper());
    bool ok = false;
    const QString hex = QInputDialog::getText(this, tr("Edit data at %1").arg(m_session->formatAddress(address)),
        tr("Hex:"), QLineEdit::Normal, current.join(QLatin1Char(' ')), &ok);
    if (!ok)
        return;
    traceAction("Edit bytes");
    m_session->writeBytes(address, hex);
}

void MainWindow::showPatches()
{
    traceAction("Patches");
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Patches"));
    dialog.resize(640, 400);
    auto* table = new TableView({tr("Address"), tr("Module"), tr("Old"), tr("New")});
    auto* restore = new QPushButton(tr("&Restore selected"));
    auto* exportButton = new QPushButton(tr("&Export..."));
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    buttons->addButton(restore, QDialogButtonBox::ActionRole);
    buttons->addButton(exportButton, QDialogButtonBox::ActionRole);
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(table);
    layout->addWidget(buttons);

    const auto refresh = [this, table] {
        QList<QStringList> rows;
        QList<std::uint64_t> keys;
        const auto hexByte = [](std::uint8_t b) { return QStringLiteral("%1").arg(b, 2, 16, QLatin1Char('0')).toUpper(); };
        for (const PatchRow& row : m_session->patchRows()) {
            rows << QStringList{m_session->formatAddress(row.address), qs(row.module), hexByte(row.original), hexByte(row.patched)};
            keys << row.address;
        }
        table->setRows(rows, keys);
    };
    refresh();
    connect(m_session, &DebugSession::memoryChanged, &dialog, refresh);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(restore, &QPushButton::clicked, &dialog, [this, table] {
        if (table->currentKey() != TableView::NoKey)
            m_session->restorePatch(table->currentKey());
    });
    connect(exportButton, &QPushButton::clicked, &dialog, [this, &dialog] {
        const QString path = QFileDialog::getSaveFileName(&dialog, tr("Save patched file"));
        if (!path.isEmpty())
            m_session->exportPatches(path);
    });
    connect(table, &TableView::rowActivated, &dialog, [this, &dialog](std::uint64_t address) {
        dialog.accept();
        onGotoRequested(CpuWidget::Disassembly, address);
    });
    dialog.exec();
}

void MainWindow::showAnnotations(int kind)
{
    static const char* titles[] = {QT_TR_NOOP("Comments"), QT_TR_NOOP("Labels"), QT_TR_NOOP("Bookmarks")};
    QDialog dialog(this);
    dialog.setWindowTitle(tr(titles[qBound(0, kind, 2)]));
    dialog.resize(640, 400);
    auto* table = new TableView({tr("Address"), tr("Module"), kind == 2 ? tr("Label") : tr("Text")});
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(table);
    const auto refresh = [this, table, kind] {
        QList<QStringList> rows;
        QList<std::uint64_t> keys;
        for (const AnnotationRow& row : m_session->annotationRows(kind)) {
            rows << QStringList{m_session->formatAddress(row.address), qs(row.module), qs(row.text)};
            keys << row.address;
        }
        table->setRows(rows, keys);
    };
    refresh();
    connect(m_session, &DebugSession::memoryChanged, &dialog, refresh);
    connect(table, &TableView::rowActivated, &dialog, [this, &dialog](std::uint64_t address) {
        dialog.accept();
        onGotoRequested(CpuWidget::Disassembly, address);
    });
    dialog.exec();
}

void MainWindow::editBreakpoint(std::uint64_t address)
{
    const std::uint32_t number = m_session->breakpointNumberAt(address);
    if (number == 0) {
        appendLog(tr("No breakpoint at %1").arg(m_session->formatAddress(address)));
        return;
    }
    QString current;
    for (const BreakpointRow& row : m_session->breakpointRows()) {
        if (row.number == number)
            current = qs(row.condition);
    }
    bool ok = false;
    const QString condition = QInputDialog::getText(this, tr("Edit breakpoint %1").arg(m_session->formatAddress(address)),
        tr("Break condition (empty for none):"), QLineEdit::Normal, current, &ok);
    if (ok)
        m_session->setBreakpointCondition(number, condition);
}

QStringList MainWindow::shortcutConflicts() const
{
    QMap<QString, QStringList> owners;
    for (QAction* action : findChildren<QAction*>()) {
        // View-local actions (F2, Enter, Ctrl+G in each view) only apply to their own widget.
        if (action->shortcutContext() != Qt::ApplicationShortcut)
            continue;
        for (const QKeySequence& key : action->shortcuts()) {
            if (!key.isEmpty())
                owners[key.toString()] << action->text();
        }
    }
    for (QAction* menu : menuBar()->actions()) {
        const QString text = menu->text();
        const qsizetype amp = text.indexOf(QLatin1Char('&'));
        if (amp >= 0 && amp + 1 < text.size())
            owners[QKeySequence(QStringLiteral("Alt+") + text.at(amp + 1).toUpper()).toString()] << text;
    }
    QStringList conflicts;
    for (auto it = owners.cbegin(); it != owners.cend(); ++it) {
        if (it.value().size() > 1)
            conflicts << QStringLiteral("%1: %2").arg(it.key(), it.value().join(QStringLiteral(", ")));
    }
    return conflicts;
}

void MainWindow::runSmokeTest(const QString& screenshotPath)
{
    const QStringList conflicts = shortcutConflicts();
    if (!conflicts.isEmpty()) {
        for (const QString& c : conflicts)
            std::fprintf(stderr, "SHORTCUT CONFLICT %s\n", qPrintable(c));
        QTimer::singleShot(0, this, [] { QApplication::exit(4); });
        return;
    }
    QTimer::singleShot(30000, this, [] {
        std::fprintf(stderr, "SMOKE FAIL: timed out\n");
        QApplication::exit(2);
    });

    auto finish = [this, screenshotPath] {
        showTab(m_cpu);
        // Give background memory fetches time to arrive and repaint.
        QTimer::singleShot(1500, this, [this, screenshotPath] {
            const bool saved = grab().save(screenshotPath);
            const std::uint64_t pc = m_session->currentAddress();
            std::printf("SMOKE %s: %s; paused at %s %s\n", saved ? "OK" : "FAIL", qPrintable(m_gdbVersion),
                qPrintable(m_session->formatAddress(pc)), qPrintable(m_session->label(pc)));
            std::fflush(stdout);
            QApplication::exit(saved ? 0 : 3);
        });
    };
    if (m_pendingExecutable.isEmpty()) {
        connect(m_session, &DebugSession::gdbReady, this, finish, Qt::SingleShotConnection);
        return;
    }
    // First pause: system breakpoint; F9 then stops at the entry breakpoint.
    auto pauses = std::make_shared<int>(0);
    connect(m_session, &DebugSession::paused, this, [this, pauses, finish](std::uint64_t) {
        if (++*pauses == 1)
            m_session->run();
        else if (*pauses == 2)
            finish();
    });
}
