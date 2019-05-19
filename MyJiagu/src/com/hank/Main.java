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

	private static final String unzipedDir = "unziped";// ԭapk��ѹ֮��Ĵ��λ��
	private static final String shellAarDir = "shell";// ��aar�Ĵ��λ��
	private static final String oriDexFileName = "classes.dex";
	private static final String oriApkName = "app-debug.apk";
	private static final String oriApkFolder = "apks";
	private static final String shellAARFileName = "shell-debug.aar";

	public static void main(String[] args) {
		// apk�ָ�����ӹ�ǰ����ԭapk���ӹ̺󣬽� �Ѽӹ�apk
		// ������ʼ��apk���мӹ�
		System.out.println("������ʼ��apk���мӹ�");
		// 1)��ԭapk���н�ѹ��������һ��Ŀ¼
		String oriApkPath = oriApkFolder + "/" + oriApkName;
		File oriApkFile = new File(oriApkPath);
		if (oriApkFile.exists()) {
			System.out.println("�ļ��Ѵ���");
		}

		// ������ѹ֮��Ĵ��Ŀ¼
		File unzipedDirFile = new File(unzipedDir);

		emptyFolder(unzipedDir, unzipedDirFile);

		if (!unzipedDirFile.exists()) {
			unzipedDirFile.mkdirs();
		}
		Zip.unZip(oriApkFile, unzipedDirFile);// ��unzipedĿ¼�У����ǵõ��˽�ѹ֮�����������
		// 2)ȡ�����е�dex�ļ����飬��Ϊʲô�����飿��Ϊһ��apk�п�����������������lib�Ӷ����ɶ��dex��
		String[] oriDexes = unzipedDirFile.list(new FilenameFilter() {

			@Override
			public boolean accept(File dir, String name) {
				if (name.endsWith(".dex"))
					return true;
				return false;
			}
		});

		printStringArray(oriDexes);//

		// 3)�����������е�dex����AES���ܣ�ȡ��ԭ����dex
		AES.init(AES.DEFAULT_PWD);// ������Կ
		for (int i = 0; i < oriDexes.length; i++) {
			File oriDexFile = new File(unzipedDirFile + "/" + oriDexes[i]);
			// ����Щ�ļ���ÿһ���ֽڽ��м���
			// ��ȡ�����е��ֽ�
			try {
				byte[] buf = getFullBytes(oriDexFile);

				// ���е��ֽڶ������buf���棬���ڱ�������ÿһ���ֽڶ�����AES����
				byte[] encryptedBuf = AES.encrypt(buf);// �õ��˼���֮����ֽ�����
				// ���ڰѼ���֮����ֽ�����д���ԭ�����ļ������ˣ��������´���Ŀ¼��
				String encryptedFileName = unzipedDirFile + "/" + "_" + oriDexes[i];// ����һ���º���
				BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(encryptedFileName));
				bos.write(encryptedBuf);
				bos.flush();
				bos.close();
				// ��������Ҿ͵õ������е�Դdex�����м���֮���dex

				// ����ɾ��ԭ����û���ܵ��ļ�
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

		// 4)����dex Ҳ�ŵ��Ǹ�Ŀ¼��
		File shellAarFile = new File(shellAarDir + "/" + shellAARFileName);
		// ��ô������Ǳ��һ��dex�أ�
		try {
			File shellDexFile = Dx.jar2Dex(shellAarFile);
			// д�뵽���unzipedĿ¼��
			// ��ȡ����ȫ���ֽ�����
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

		// ���ˣ����ǵõ����µ�apk�������ݣ���Ҫ�����Ǵ��apk�ļ�
		// 5)��Ŀ¼����ѹ����jar����Ȼ�������������apk
		File jiaguUnsinged = new File("apks/jiagu_unsign.apk");
		File dir = new File(unzipedDir);
		if (jiaguUnsinged.exists())
			jiaguUnsinged.delete();
		try {
			Zip.zip(dir, jiaguUnsinged);

		} catch (Exception e) {
			e.printStackTrace();
		}

		// 6)Ŀǰ�õ���һ��δǩ����apk����������ǩ����Ҫʹ��ԭ��ʹ�ù���keystore,
		// ��������ǵõ�����ǩ�����Ѽӹ̵�apk.
		File signedApk = new File("apks/jiagu_signed.apk");
		File unsignApk = new File("apks/jiagu_unsign.apk");
		try {
			Signature.signature(unsignApk, signedApk);
		} catch (InterruptedException | IOException e) {
			e.printStackTrace();
		}

		// ����Դdex�Ѿ����ܣ��ڲ�֪����Կ��������޷��ƽ⣬�����Ѽӹ̵�apk�����ȫ

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
	 * ɾ��һ��Ŀ¼�µ������ļ������Զ���Ŀ¼�µ��ļ����Ӱ��
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
