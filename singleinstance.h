#pragma once
#include <QObject>
#include <QLocalServer>
#include <QLocalSocket>

class SingleInstance : public QObject {
    Q_OBJECT
public:
    explicit SingleInstance(QString key, QObject* parent = nullptr)
        : QObject(parent), m_key(std::move(key)), m_server(new QLocalServer(this)) {}

    bool tryRunAsPrimary(int connectTimeoutMs = 200) {
        QLocalSocket probe;
        probe.connectToServer(m_key, QIODevice::WriteOnly);
        if (probe.waitForConnected(connectTimeoutMs)) {
            probe.disconnectFromServer();
            return false;
        }

        QLocalServer::removeServer(m_key);
        if (!m_server->listen(m_key)) {
            return false;
        }
        connect(m_server, &QLocalServer::newConnection, this, &SingleInstance::onNewConnection);
        return true;
    }

    bool sendMessage(const QByteArray& msg, int timeoutMs = 500) {
        QLocalSocket socket;
        socket.connectToServer(m_key, QIODevice::WriteOnly);
        if (!socket.waitForConnected(timeoutMs)) return false;
        socket.write(msg);
        bool ok = socket.waitForBytesWritten(timeoutMs);
        socket.flush();
        socket.disconnectFromServer();
        return ok;
    }

signals:
    void messageReceived(const QByteArray& msg);

private slots:
    void onNewConnection() {
        while (m_server->hasPendingConnections()) {
            QLocalSocket* client = m_server->nextPendingConnection();
            connect(client, &QLocalSocket::readyRead, this, [this, client]() {
                QByteArray data = client->readAll();
                emit messageReceived(data);
                client->disconnectFromServer();
                client->deleteLater();
            });
        }
    }

private:
    QString m_key;
    QLocalServer* m_server;
};
