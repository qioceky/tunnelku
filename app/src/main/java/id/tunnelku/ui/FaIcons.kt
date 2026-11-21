package id.tunnelku.ui

import android.content.Context
import android.graphics.Typeface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.sp

/**
 * Ikon Font Awesome Free Solid 6.5.2 — font dibundel lokal di
 * assets/fonts/fa-solid-900.ttf (offline, tanpa CDN).
 * Lisensi Font Awesome Free: ikon CC BY 4.0 — atribusi ada di tab Atur.
 * Semua kode glif diverifikasi dari cmap font itu sendiri.
 */
object Fa {
    const val HOUSE = "\uF015"
    const val SERVER = "\uF233"
    const val TERMINAL = "\uF120"
    const val GEAR = "\uF013"
    const val BOLT = "\uF0E7"
    const val POWER = "\uF011"
    const val PLUS = "\uF067"
    const val COPY = "\uF0C5"
    const val TRASH = "\uF2ED"
    const val IMAGE = "\uF03E"
    const val PALETTE = "\uF53F"
    const val WINDOW = "\uF2D0"
    const val CIRCLE_CHECK = "\uF058"
    const val CIRCLE = "\uF111"
    const val PLUG = "\uF1E6"
    const val KEY = "\uF084"
    const val GLOBE = "\uF0AC"
    const val CHECK = "\uF00C"
    const val LINK = "\uF0C1"
    const val TOWER = "\uF519"
}

private object FaTypeface {
    @Volatile
    private var cached: Typeface? = null

    fun get(context: Context): Typeface =
        cached ?: synchronized(this) {
            cached ?: Typeface.createFromAsset(
                context.applicationContext.assets, "fonts/fa-solid-900.ttf"
            ).also { cached = it }
        }
}

/** Satu glif Font Awesome sebagai teks ber-font FA. */
@Composable
fun FaIcon(
    icon: String,
    modifier: Modifier = Modifier,
    size: TextUnit = 16.sp,
    color: Color = Color.White
) {
    val context = LocalContext.current
    val typeface = remember { FaTypeface.get(context) }
    Text(
        icon,
        modifier = modifier,
        fontFamily = FontFamily(typeface),
        fontSize = size,
        color = color
    )
}
