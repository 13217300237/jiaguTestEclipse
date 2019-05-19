package com.hank;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.List;

import com.hank.tools.AES;
import com.hank.tools.Dx;
import com.hank.tools.Signature;
import com.hank.tools.Zip;

public class Main {

	private static final String unzipedDir = "unziped";// 原apk解压之后的存放位置
	private static final String shellAarDir = "shell";// 壳aar的存放位置
	private static final String oriDexFileName = "classes.dex";
	private static final String oriApkName = "app-debug.apk";
	private static final String oriApkFolder = "apks";
	private static final String shellAARFileName = "shell-debug.aar";

	public static void main(String[] args) {
		// apk分个概念：加固前，叫原apk，加固后，叫 已加固apk
		// 即将开始对apk进行加固
		System.out.println("即将开始对apk进行加固");
		// 1)将原apk进行解压缩，生成一个目录
		String oriApkPath = oriApkFolder + "/" + oriApkName;
		File oriApkFile = new File(oriApkPath);
		if (oriApkFile.exists()) {
			System.out.println("文件已存在");
		}

		// 创建解压之后的存放目录
		File unzipedDirFile = new File(unzipedDir);

		emptyFolder(unzipedDir, unzipedDirFile);

		if (!unzipedDirFile.exists()) {
			unzipedDirFile.mkdirs();
		}
		Zip.unZip(oriApkFile, unzipedDirFile);// 在unziped目录中，我们得到了解压之后的所有内容
		// 2)取得其中的dex文件数组，（为什么是数组？因为一个apk中可能引用其他第三方lib从而生成多个dex）
		String[] oriDexes = unzipedDirFile.list(new FilenameFilter() {

			@Override
			public boolean accept(File dir, String name) {
				if (name.endsWith(".dex"))
					return true;
				return false;
			}
		});

		printStringArray(oriDexes);//

		// 3)遍历，对所有的dex进行AES加密，取代原来的dex
		AES.init(AES.DEFAULT_PWD);// 设置密钥
		for (int i = 0; i < oriDexes.length; i++) {
			File oriDexFile = new File(unzipedDirFile + "/" + oriDexes[i]);
			// 对这些文件的每一个字节进行加密
			// 先取得所有的字节
			try {
				byte[] buf = getFullBytes(oriDexFile);

				// 所有的字节都在这个buf里面，现在遍历它，每一个字节都进行AES加密
				byte[] encryptedBuf = AES.encrypt(buf);// 得到了加密之后的字节序列
				// 现在把加密之后的字节序列写入回原来的文件，算了，还是重新创建目录吧
				String encryptedFileName = unzipedDirFile + "/" + "_" + oriDexes[i];// 加了一个下横线
				BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(encryptedFileName));
				bos.write(encryptedBuf);
				bos.flush();
				bos.close();
				// 到了这里，我就得到了所有的源dex的所有加密之后的dex

				// 并且删除原来的没加密的文件
				if (oriDexFile.exists()) {
					oriDexFile.delete();
				}

			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		// 4)将壳dex 也放到那个目录中
		File shellAarFile = new File(shellAarDir + "/" + shellAARFileName);
		// 怎么把这个壳变成一个dex呢？
		try {
			File shellDexFile = Dx.jar2Dex(shellAarFile);
			// 写入到这个unziped目录中
			// 获取它的全部字节序列
			byte[] buf = getFullBytes(shellDexFile);

			BufferedOutputStream bos = new BufferedOutputStream(
					new FileOutputStream(unzipedDir + "/" + oriDexFileName));
			bos.write(buf);
			bos.flush();
			bos.close();

		} catch (IOException | InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// 至此，我们得到了新的apk包的内容，我要把他们打成apk文件
		// 5)将目录重新压缩成jar包，然后调用命令打包成apk
		File jiaguUnsinged = new File("apks/jiagu_unsign.apk");
		File dir = new File(unzipedDir);
		if (jiaguUnsinged.exists())
			jiaguUnsinged.delete();
		try {
			Zip.zip(dir, jiaguUnsinged);

		} catch (Exception e) {
			e.printStackTrace();
		}

		// 6)目前得到了一个未签名的apk，对他进行签名，要使用原先使用过的keystore,
		// 到这里，我们得到了已签名的已加固的apk.
		File signedApk = new File("apks/jiagu_signed.apk");
		File unsignApk = new File("apks/jiagu_unsign.apk");
		try {
			Signature.signature(unsignApk, signedApk);
		} catch (InterruptedException | IOException e) {
			e.printStackTrace();
		}

		// 由于源dex已经加密，在不知道密钥的情况下无法破解，所以已加固的apk会更安全

	}

	private static byte[] getFullBytes(File oriDexFile) {
		// TODO Auto-generated method stub
		byte[] buf = null;
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(oriDexFile, "r");

			buf = new byte[(int) oriDexFile.length()];
			raf.readFully(buf);

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			try {
				raf.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return buf;
	}

	/**
	 * 删除一个目录下的所有文件，不对二级目录下的文件造成影响
	 * 
	 * @param path
	 * @param unzipedDirFile
	 */
	private static void emptyFolder(String path, File unzipedDirFile) {
		String[] s = unzipedDirFile.list();
		for (int i = 0; i < s.length; i++) {
			File f = new File(path + "/" + s[i]);
			f.delete();
		}
	}

	private static void printStringArray(String[] arg) {
		if (arg == null) {
			System.out.println("empty arg!");
			return;
		}
		for (int i = 0; i < arg.length; i++) {
			System.out.println("" + arg[i]);
		}
	}

}
