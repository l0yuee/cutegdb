#pragma once

#include <QAbstractScrollArea>
#include <functional>

class DebugSession;

// Scrolling list view over target memory. The scroll bar only reports direction: content is
// addressed by the view itself, as in x64dbg.
class BaseView : public QAbstractScrollArea {
    Q_OBJECT

public:
    explicit BaseView(DebugSession* session, QWidget* parent = nullptr);

signals:
    void gotoExpressionRequested();

protected:
    DebugSession* session() const { return m_session; }
    int rowHeight() const;
    int charWidth() const;
    int visibleRows() const;
    virtual void scrollLines(int lines) = 0;
    void wheelEvent(QWheelEvent* event) override;
    void addViewAction(const QKeySequence& key, std::function<void()> handler);

private:
    DebugSession* m_session;
};
