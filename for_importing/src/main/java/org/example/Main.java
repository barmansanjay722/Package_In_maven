package org.example;

import org.commonOps.CommonUtils;
import org.example.my_mathematics.MyMath;

public class Main {
    public static void main(String[] args) {

        MyMath myMath = new MyMath();
        int res =  myMath.sumTwoNums(1,3);
        System.out.println(res);

        String randomUuidNumb = CommonUtils.generateUUID();
        System.out.println(randomUuidNumb);

        String pascal = CommonUtils.convertToPascalCase("sanjay");
        System.out.println(pascal);
    }
}