#pragma once

#include "cutegdb/src/session.cxxqt.h"

#include <QWidget>

class RegistersView : public QWidget {
    Q_OBJECT

public:
    explicit RegistersView(DebugSession* session, QWidget* parent = nullptr);
    void refresh();

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    DebugSession* m_session;
    rust::Vec<RegisterRow> m_rows;
};
