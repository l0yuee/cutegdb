#include "baseview.h"
#include "theme.h"

#include <QAction>
#include <QScrollBar>
#include <QWheelEvent>

BaseView::BaseView(DebugSession* session, QWidget* parent)
    : QAbstractScrollArea(parent)
    , m_session(session)
{
    setFont(theme::monospaceFont());
    setFocusPolicy(Qt::StrongFocus);
    setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    QScrollBar* bar = verticalScrollBar();
    bar->setRange(0, 100);
    bar->setPageStep(10);
    bar->setValue(50);
    connect(bar, &QAbstractSlider::actionTriggered, this, [this, bar](int action) {
        switch (action) {
        case QAbstractSlider::SliderSingleStepAdd:
            scrollLines(1);
            break;
        case QAbstractSlider::SliderSingleStepSub:
            scrollLines(-1);
            break;
        case QAbstractSlider::SliderPageStepAdd:
            scrollLines(visibleRows());
            break;
        case QAbstractSlider::SliderPageStepSub:
            scrollLines(-visibleRows());
            break;
        default:
            break;
        }
        bar->setSliderPosition(50);
    });

    addViewAction(QKeySequence(QStringLiteral("Ctrl+G")), [this] { emit gotoExpressionRequested(); });
}

int BaseView::rowHeight() const
{
    return fontMetrics().height() + 2;
}

int BaseView::charWidth() const
{
    return fontMetrics().horizontalAdvance(QLatin1Char('0'));
}

int BaseView::visibleRows() const
{
    return qMax(1, viewport()->height() / rowHeight());
}

void BaseView::wheelEvent(QWheelEvent* event)
{
    const int steps = event->angleDelta().y() / 120;
    if (steps != 0)
        scrollLines(-steps * 3);
    event->accept();
}

void BaseView::addViewAction(const QKeySequence& key, std::function<void()> handler)
{
    auto* action = new QAction(this);
    action->setShortcut(key);
    action->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    connect(action, &QAction::triggered, this, std::move(handler));
    addAction(action);
}
