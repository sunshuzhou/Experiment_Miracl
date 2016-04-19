package com.sunshuzhou.experiment_miracl;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.SystemClock;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;

import org.json.JSONException;
import org.json.JSONObject;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class MainActivity extends AppCompatActivity {

    EditText userPass;
    EditText userId;
    Button buttonSure;
    Button buttonEnroll;
    Context context;
    TextView textViewLogInfo;

    RequestQueue requestQueue = null;

    void writeLog(String msg) {
        textViewLogInfo.setText(textViewLogInfo.getText().toString() + "\n" + msg);
        Log.i("info", msg);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });

        valueFromJNI();

        context = this;
        requestQueue = Volley.newRequestQueue(this);

        userPass = (EditText) findViewById(R.id.userPass);
        userId = (EditText) findViewById(R.id.userId);
        buttonSure = (Button) findViewById(R.id.buttonSure);
        buttonEnroll = (Button) findViewById(R.id.buttonEnroll);
        textViewLogInfo = (TextView) findViewById(R.id.logInfo);

        buttonSure.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // 按钮点击事件，开始进行认证
                final List<Integer> integerList = new ArrayList<Integer>();
                final long t0 = System.currentTimeMillis();
                final BigInteger alpha = Verify.fromPassword(userPass.getText().toString());
                textViewLogInfo.setText("");
//                writeLog("alpha: " + alpha.toString());
                final BigInteger beta = BigInteger.ONE;
                final SharedPreferences preferences = context.getSharedPreferences(getString(R.string.preferences_name), Context.MODE_PRIVATE);
                String tempString = preferences.getString(getString(R.string.gama) + userId.getText().toString(), "");
//                writeLog("gama: " + tempString);
                writeLog("Start to communcation.");
                if (tempString.length() != 0) {
                    final BigInteger gama = new BigInteger(tempString);
                    //writeLog("gama:" + gama.toString());
                    ECPoint zeta = Config.ECC_G.multiply(alpha.add(beta).add(gama));
                    Map<String, String> stringStringMap = new HashMap<String, String>();
                    final long t1 = System.currentTimeMillis();
                    integerList.add((int)(t1 - t0));
                    stringStringMap.put("u", userId.getText().toString());
                    // 开始验证，发送请求
                    // 参数 u: userid
                    StringRequest stringRequest = new StringRequest(Request.Method.POST,
                            Config.SERVER_ADDRESS + "generatechallenge.php",
                            new Response.Listener<String>() {
                                @Override
                                public void onResponse(String response) {
                                    try {
                                        final JSONObject jsonObject = new JSONObject(response);
                                        writeLog("Compute Server Challenge.");
                                        final String message = jsonObject.get("message").toString();
                                        if (message.equals("1")) {
                                            // 得到challenge，计算challenge
                                            final long serverTime1 = Integer.valueOf(jsonObject.get("time").toString());
                                            final long t2 = System.currentTimeMillis();
                                            jsonObject.put("alpha", alpha.toString(16));
                                            jsonObject.put("beta", beta.toString(16));
                                            jsonObject.put("gama", gama.toString(16));
                                            final Map<String, String> params = Verify.compute(jsonObject, alpha.add(beta).add(gama));
                                            long t3 = System.currentTimeMillis();
                                            integerList.add((int)(t3 - t2));
                                            final String localKeyInMemory = params.get("key").toString();
                                            params.put("key", "");
//                                            writeLog("Client Key: "+ localKeyInMemory);
//                                            writeLog("Client Message m0: " + params.get("message0"));
//                                            writeLog("Client Tag t0: " + params.get("tag0"));
                                            writeLog("Send (m0, t0) to Server.");
                                            StringRequest stringRequest1 = new StringRequest(Request.Method.POST,
                                                    Config.SERVER_ADDRESS + "login.php",
                                                    new Response.Listener<String>() {
                                                        @Override
                                                        public void onResponse(String response) {
                                                            try {
                                                                // 查看服务器验证的结果，同时在本地验证
                                                                JSONObject jsonObject1 = new JSONObject(response);
                                                                String message1 = jsonObject1.get("success").toString();
                                                                if (message1.equals("1")) {
                                                                    writeLog("Server Verified Success.");
                                                                    long t4 = System.currentTimeMillis();
                                                                    final long serverTime2 = Integer.valueOf(jsonObject1.get("time").toString());
                                                                    boolean v = Verify.verify(localKeyInMemory, jsonObject1.get("m1").toString(), jsonObject1.get("t1").toString());
                                                                    long t5 = System.currentTimeMillis();
                                                                    integerList.add((int)(t5 - t4));
                                                                    writeLog("Mac(K, m1, t1): " + String.valueOf(v));
                                                                    writeLog("Total used Time:" + String.valueOf(t5 - t0));
                                                                    long cTime = 0;
                                                                    for (int i = 0; i < integerList.size(); i++) {
                                                                        cTime += integerList.get(i);
                                                                    }
                                                                    writeLog("Client Time: " + String.valueOf(cTime));
                                                                    writeLog("Server Time: " + String.valueOf(serverTime1 + serverTime2));
                                                                    writeLog("Communication Time: " + String.valueOf(t5-t0-cTime - serverTime1 - serverTime2));
                                                                    if (v) {
                                                                        writeLog("Client Verified Success.");
                                                                    } else {
                                                                        writeLog("Client Verified Failed.");
                                                                    }
                                                                } else {
                                                                    writeLog("Server Verified Failed.");
                                                                }
                                                            } catch (JSONException e) {
                                                                e.printStackTrace();
                                                            }
                                                        }
                                                    }, new Response.ErrorListener() {
                                                            @Override
                                                            public void onErrorResponse(VolleyError error) {
                                                                error.printStackTrace();
                                                            }
                                            }) {
                                                @Override
                                                protected Map<String, String> getParams() throws AuthFailureError {
                                                    return params;
                                                }
                                            };
                                            requestQueue.add(stringRequest1);
                                            requestQueue.start();
                                        } else if (message.equals("2")) {
                                            Toast.makeText(context, "用户未注册。", Toast.LENGTH_SHORT).show();
                                        } else if (message.equals("0")) {
                                            Toast.makeText(context, "正在验证，请不要重复点击。", Toast.LENGTH_SHORT).show();
                                        } else {
                                            Toast.makeText(context, "缺乏必要的参数。", Toast.LENGTH_SHORT).show();
                                        }
                                    } catch (JSONException e) {
                                        e.printStackTrace();
                                    }
                                }
                            },
                            new Response.ErrorListener() {
                                @Override
                                public void onErrorResponse(VolleyError error) {
                                    error.printStackTrace();
                                }
                            }) {
                        @Override
                        protected Map<String, String> getParams() throws AuthFailureError {
                            Map<String, String> m = new HashMap<String, String>();
                            m.put("u", userId.getText().toString());
                            return m;
                        }
                    };
                    requestQueue.add(stringRequest);
                    requestQueue.start();
                } else {
                    Toast.makeText(context, "该用户未授权此设备使用！", Toast.LENGTH_SHORT).show();
                }
            }
        });


        buttonEnroll.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                long t0 = System.currentTimeMillis();
                BigInteger alpha = Verify.fromPassword(userPass.getText().toString());
                BigInteger beta = BigInteger.ONE;

                // 注册，随机选择默认的gama
                final BigInteger gama = BigInteger.probablePrime(Config.ECC_K, new SecureRandom());
                // (alpha + beta + gama) * G
                ECPoint zeta = Config.ECC_G.multiply(alpha.add(beta).add(gama));
                final ECPoint finalECPoint = zeta.normalize();

                StringRequest stringRequest = new StringRequest(Request.Method.POST, Config.SERVER_ADDRESS + "enroll.php", new Response.Listener<String>() {
                    @Override
                    public void onResponse(String response) {
                        Log.i("RESPONSE: ", response);
                        if (response.equals("1")) {
                            SharedPreferences preferences = context.getSharedPreferences(getString(R.string.preferences_name), Context.MODE_PRIVATE);
                            SharedPreferences.Editor editor = preferences.edit();
                            editor.putString(getString(R.string.gama) + userId.getText().toString(), gama.toString());
                            editor.commit();
                            Toast.makeText(context, "在此设备注册成功，允许使用此设备登陆。", Toast.LENGTH_SHORT).show();
                        } else {
                            Toast.makeText(context, "注册失败，该用户名已存在！", Toast.LENGTH_SHORT).show();
                        }
                    }
                }, new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        Log.e("NETWORK:", error.getMessage());
                    }
                }) {
                    @Override
                    protected Map<String, String> getParams() throws AuthFailureError {
                        Map<String, String> map = new HashMap<String, String>();
                        map.put("u", userId.getText().toString());
                        map.put("zx", finalECPoint.getXCoord().toString());
                        map.put("zy", finalECPoint.getYCoord().toString());
                        return map;
                    }
                };
                requestQueue.add(stringRequest);
                requestQueue.start();
            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    static {
        //System.loadLibrary("miracl");
        System.loadLibrary("experiment");
    }

    public native int valueFromJNI();
}
