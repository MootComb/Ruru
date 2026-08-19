package icu.nullptr.applistdetector

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build

import java.util.zip.ZipFile

class XposedModules(
    context: Context,
    override val name: String,
    private val lspatch: Boolean
) : IDetector(context) {

    @SuppressLint("QueryPermissions OR PMCAPermissions Needed")
    override fun run(packages: Collection<String>?, detail: Detail?): Result {
        if (packages != null) throw IllegalArgumentException("packages should be null")

        var result = Result.NOT_FOUND
        val pm = context.packageManager
        val set = if (detail == null) null else mutableSetOf<Pair<String, Result>>()

        val intent=Intent(Intent.ACTION_MAIN)
        val apps = pm.queryIntentActivities(intent,PackageManager.GET_META_DATA)
            .map { it.activityInfo.applicationInfo }
            .distinctBy { it.packageName }

        val XpmetaList= listOf("xposedminversion", "xposeddescription")
        val LspmetaList= listOf("lspatch","npatch","jshook")
        val XposedPatch = listOf("META-INF/xposed/module.prop")

        for (pkg in apps) {
            val meta = pkg.metaData
            val label = pm.getApplicationLabel(pkg) as String
            var found = false
            var hasxppatch =false
            var extraTag = ""
            val hasXpmeta=XpmetaList.any { meta?.containsKey(it) ==true }
            val hasLspmeta=LspmetaList.any { meta?.containsKey(it) ==true }
            val getLspmeta=LspmetaList.firstOrNull{ meta?.containsKey(it)==true }
            val apkPath = pkg.sourceDir
            try {
                ZipFile(apkPath).use { zip ->
                    hasxppatch=XposedPatch.any { zip.getEntry(it)!=null }
                }
            } catch (e: Exception) {
            }
            var haslspfact = false
            if (Build.VERSION.SDK_INT >=Build.VERSION_CODES.P){
                pkg.appComponentFactory?.let { factory ->
                    if (factory.contains("lsposed")){
                        haslspfact = true
                    }
                }
            }
            if (lspatch){
                found = hasLspmeta || haslspfact
                when{
                    haslspfact -> extraTag ="(Api28)"
                    getLspmeta !=null -> extraTag= "(${getLspmeta})"
                }
            }else{
                found =(hasXpmeta || hasxppatch) && !hasLspmeta
                if (hasxppatch){
                    extraTag="(libxposed 101)"
                }
            }
            if (found) {
                result = Result.FOUND
                set?.add( label+extraTag to Result.FOUND)
            }
        }

        detail?.addAll(set ?: emptySet())
        return result
    }
}
