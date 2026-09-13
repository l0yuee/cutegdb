#include "cpuwidget.h"
#include "disassemblyview.h"
#include "dumpview.h"
#include "registersview.h"
#include "stackview.h"
#include "theme.h"

#include <QDataStream>
#include <QLabel>
#include <QPlainTextEdit>
#include <QScrollArea>
#include <QSplitter>
#include <QTabWidget>
#include <QVBoxLayout>

namespace {

QPlainTextEdit* makeTextPane()
{
    auto* edit = new QPlainTextEdit;
    edit->setReadOnly(true);
    edit->setFont(theme::monospaceFont());
    edit->setLineWrapMode(QPlainTextEdit::NoWrap);
    QPalette palette = edit->palette();
    palette.setColor(QPalette::Base, theme::Background);
    palette.setColor(QPalette::Text, theme::Text);
    edit->setPalette(palette);
    return edit;
}

QSplitter* split(Qt::Orientation orientation, QWidget* first, QWidget* second, int firstStretch, int secondStretch)
{
    auto* splitter = new QSplitter(orientation);
    splitter->addWidget(first);
    splitter->addWidget(second);
    splitter->setStretchFactor(0, firstStretch);
    splitter->setStretchFactor(1, secondStretch);
    return splitter;
}

} // namespace

CpuWidget::CpuWidget(DebugSession* session, QWidget* parent)
    : QWidget(parent)
    , m_session(session)
{
    m_disassembly = new DisassemblyView(session);
    m_info = makeTextPane();
    m_info->setMinimumHeight(60);

    m_registers = new RegistersView(session);
    auto* registersScroll = new QScrollArea;
    registersScroll->setWidget(m_registers);
    registersScroll->setWidgetResizable(true);

    m_argumentsHeader = new QLabel;
    m_arguments = makeTextPane();
    auto* argumentsPane = new QWidget;
    auto* argumentsLayout = new QVBoxLayout(argumentsPane);
    argumentsLayout->setContentsMargins(0, 0, 0, 0);
    argumentsLayout->setSpacing(0);
    argumentsLayout->addWidget(m_argumentsHeader);
    argumentsLayout->addWidget(m_arguments);

    m_dumpTabs = new QTabWidget;
    for (int i = 1; i <= 5; ++i) {
        auto* dump = new DumpView(session);
        m_dumps << dump;
        m_dumpTabs->addTab(dump, tr("Dump %1").arg(i));
        connect(dump, &BaseView::gotoExpressionRequested, this, [this] { emit gotoExpressionRequested(Dump); });
    }
    m_stack = new StackView(session);

    auto* left = split(Qt::Vertical, m_disassembly, m_info, 5, 1);
    auto* right = split(Qt::Vertical, registersScroll, argumentsPane, 3, 1);
    auto* top = split(Qt::Horizontal, left, right, 3, 1);
    auto* bottom = split(Qt::Horizontal, m_dumpTabs, m_stack, 3, 2);
    auto* main = split(Qt::Vertical, top, bottom, 3, 2);
    m_splitters = {left, right, top, bottom, main};
    // Initial proportions close to x64dbg's default layout; stretch factors keep them on resize.
    left->setSizes({520, 90});
    right->setSizes({440, 140});
    top->setSizes({900, 380});
    main->setSizes({560, 260});
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(main);

    connect(session, &DebugSession::paused, this, &CpuWidget::onPaused);
    connect(session, &DebugSession::memoryChanged, this, &CpuWidget::refreshAll);
    connect(session, &DebugSession::symbolsChanged, this, &CpuWidget::refreshAll);
    connect(session, &DebugSession::breakpointsChanged, this, [this] { m_disassembly->viewport()->update(); });
    connect(session, &DebugSession::stateChanged, this, [this](int state) {
        // A new process (restart, attach, remote) has different stack and heap addresses.
        if (state == 0) {
            for (DumpView* dump : m_dumps)
                dump->reset();
        }
        m_disassembly->viewport()->update();
        m_stack->viewport()->update();
    });
    connect(m_disassembly, &DisassemblyView::selectionChanged, this, &CpuWidget::updateInfo);
    connect(m_disassembly, &BaseView::gotoExpressionRequested, this, [this] { emit gotoExpressionRequested(Disassembly); });
    connect(m_stack, &BaseView::gotoExpressionRequested, this, [this] { emit gotoExpressionRequested(Stack); });
}

QByteArray CpuWidget::saveLayout() const
{
    QByteArray layout;
    QDataStream stream(&layout, QIODevice::WriteOnly);
    for (const QSplitter* splitter : m_splitters)
        stream << splitter->saveState();
    return layout;
}

void CpuWidget::restoreLayout(const QByteArray& layout)
{
    QDataStream stream(layout);
    for (QSplitter* splitter : m_splitters) {
        QByteArray state;
        stream >> state;
        if (stream.status() != QDataStream::Ok)
            return;
        splitter->restoreState(state);
    }
}

void CpuWidget::gotoView(int view, std::uint64_t address)
{
    switch (view) {
    case Disassembly:
        m_disassembly->gotoAddress(address, true);
        m_disassembly->setFocus();
        break;
    case Dump:
        m_dumps[m_dumpTabs->currentIndex()]->gotoAddress(address);
        break;
    case Stack:
        m_stack->gotoAddress(address);
        break;
    default:
        break;
    }
}

void CpuWidget::onPaused(std::uint64_t pc)
{
    m_disassembly->followCip(pc);
    m_stack->followStackPointer(m_session->stackPointer());
    if (!m_dumps.first()->isLoaded())
        m_dumps.first()->gotoAddress(m_session->stackPointer());
    m_registers->refresh();
    updateArguments();
    updateInfo(m_disassembly->selectedAddress());
}

void CpuWidget::refreshAll()
{
    m_disassembly->reload();
    m_stack->reload();
    for (DumpView* dump : m_dumps)
        dump->reload();
    m_registers->refresh();
    updateArguments();
    updateInfo(m_disassembly->selectedAddress());
}

void CpuWidget::updateInfo(std::uint64_t address)
{
    if (m_session->debugState() == 0)
        return;
    const QString text = m_session->instructionInfo(address);
    if (m_info->toPlainText() != text)
        m_info->setPlainText(text);
}

void CpuWidget::updateArguments()
{
    m_argumentsHeader->setText(m_session->callingConvention());
    QStringList lines;
    const auto rows = m_session->argumentRows(5);
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const StackRow& row = rows[i];
        const QString value = row.readable ? m_session->formatAddress(row.value) : QStringLiteral("???");
        QString line = QStringLiteral("%1: %2 %3").arg(i + 1).arg(qs(row.name), -8).arg(value);
        if (!row.comment.empty())
            line += QStringLiteral(" <%1>").arg(qs(row.comment));
        lines << line;
    }
    const QString text = lines.join(QLatin1Char('\n'));
    if (m_arguments->toPlainText() != text)
        m_arguments->setPlainText(text);
}
