/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

/* Boneh-Lynn-Shacham signature API Functions */

package org.apache.milagro.amcl.XXX;

import org.apache.milagro.amcl.RAND;
import org.apache.milagro.amcl.SHA3;

public class BLS192
{
	public static final int BFS=BIG.MODBYTES;
	public static final int BGS=BIG.MODBYTES;
	public static final int BLS_OK=0;
	public static final int BLS_FAIL=-1;


/* hash a message to an ECP point, using SHA3 */

	static ECP bls_hashit(String m)
	{
		SHA3 sh=new SHA3(SHA3.SHAKE256);
		byte[] hm=new byte[BFS];
		byte[] t=m.getBytes();
		for (int i=0;i<t.length;i++)
			sh.process(t[i]);
		sh.shake(hm,BFS);    
		ECP P=ECP.mapit(hm);
		return P;
	}

/* generate key pair, private key S, public key W */

	public static int KeyPairGenerate(RAND RNG,byte[] S,byte[] W)
	{
		ECP4 G=ECP4.generator();
		BIG q=new BIG(ROM.CURVE_Order);
		BIG s=BIG.randomnum(q,RNG);
		s.toBytes(S);
		G=PAIR192.G2mul(G,s);
		G.toBytes(W);
		return BLS_OK;
	}

/* Sign message m using private key S to produce signature SIG */

	public static int sign(byte[] SIG,String m,byte[] S)
	{
		ECP D=bls_hashit(m);
		BIG s=BIG.fromBytes(S);
		D=PAIR192.G1mul(D,s);
		D.toBytes(SIG,true);
		return BLS_OK;
	}

/* Verify signature given message m, the signature SIG, and the public key W */

	public static int verify(byte[] SIG,String m,byte[] W)
	{
		ECP HM=bls_hashit(m);
		ECP D=ECP.fromBytes(SIG);
		ECP4 G=ECP4.generator();
		ECP4 PK=ECP4.fromBytes(W);
		D.neg();
		FP24 v=PAIR192.ate2(G,D,PK,HM);
		v=PAIR192.fexp(v);
		if (v.isunity())
			return BLS_OK;
		return BLS_FAIL;
	}
}