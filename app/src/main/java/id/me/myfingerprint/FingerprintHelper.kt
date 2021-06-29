package id.me.myfingerprint

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.CancellationSignal
import android.widget.Toast
import androidx.core.app.ActivityCompat

class FingerprintHelper(private val appContext: Context) : FingerprintManager.AuthenticationCallback() {

    lateinit var cancellationSignal: CancellationSignal

    fun startAuth(manager: FingerprintManager,
                  cryptoObject: FingerprintManager.CryptoObject) {

        cancellationSignal = CancellationSignal()

        if (ActivityCompat.checkSelfPermission(appContext,
                Manifest.permission.USE_FINGERPRINT) !=
            PackageManager.PERMISSION_GRANTED) {
            return
        }
        manager.authenticate(cryptoObject, cancellationSignal, 0, this, null)
    }

    override fun onAuthenticationError(errMsgId: Int,
                                       errString: CharSequence) {
        Toast.makeText(appContext, "Autentifikasi bermasalah \n" + errString,
            Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationHelp(helpMsgId: Int,
                                      helpString: CharSequence) {
        Toast.makeText(appContext,
            "Autentifikasi membutuhkan bantuan \n" + helpString,
            Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationFailed() {
        Toast.makeText(appContext,
            "Autentifikasi gagal.",
            Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationSucceeded(
        result: FingerprintManager.AuthenticationResult) {

        Toast.makeText(appContext,
            "Autentifikasi berhasil.",
            Toast.LENGTH_LONG).show()
    }
}