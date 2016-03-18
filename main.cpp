#include <QCoreApplication>
#include <QDebug>
#include <QThread>
#include <QObject>
#include <iostream>

#include <pwdgenerator.h>
#include "SignalHandler.h"

class Application : public SignalHandler
{
public:
    Application() : SignalHandler(SignalHandler::SIG_INT), pwdGenerator(NULL) {}

    int Application::main(int argc, char *argv[])
    {
        // Main program instructions here (e.g. start a thread)
        QCoreApplication consoleApplication(argc, argv);

        consoleApplication.thread()->setObjectName("Console Thread");

        pwdGenerator = new PwdGenerator();

        pwdGenerator->moveToThread(&threadPwdGenerator);

        // Name the threads (helpful for debugging)
        threadPwdGenerator.setObjectName("PwdGenerator Thread");

        // DELETE LATER
        QObject::connect(&threadPwdGenerator, SIGNAL(finished()),
                        pwdGenerator, SLOT(deleteLater()));

        QObject::connect(&consoleApplication, SIGNAL(aboutToQuit()),
                        pwdGenerator, SLOT(stopPwdGenFSM()));

        QObject::connect(pwdGenerator, SIGNAL(quitPwdGenerator()),
                        &consoleApplication, SLOT(quit()));

        // start the thread
        threadPwdGenerator.start();

        QMetaObject::invokeMethod(pwdGenerator, "startPwdGenFSM", Qt::AutoConnection);

        int consoleReturn =  consoleApplication.exec();

        //qDebug() << "Stop Thread";
        threadPwdGenerator.quit();
        threadPwdGenerator.wait();
        //qDebug() << "Application will end now";

        //delete pwdGenerator;

        return consoleReturn;
    }

    bool handleSignal(int signal)
    {
        std::cout << "Handling signal " << signal << std::endl;
        if (threadPwdGenerator.isRunning())
        {
            QMetaObject::invokeMethod(pwdGenerator, "stopPwdGenFSM", Qt::AutoConnection);
            return true;
        }
        // Let the signal propagate as though we had not been there
        return false;
    }
private:
    //thread for the Password generator
    QThread threadPwdGenerator;
    PwdGenerator *pwdGenerator;
};

int main(int argc, char *argv[])
{
    // http://stackoverflow.com/questions/7581343/how-to-catch-ctrlc-on-windows-and-linux-with-qt
    Application app;

    return app.main(argc, argv);
}

