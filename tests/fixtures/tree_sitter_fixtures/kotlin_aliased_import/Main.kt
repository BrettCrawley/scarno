package com.example

import com.foo.Bar as B
import org.springframework.stereotype.Service as SpringService
import kotlinx.coroutines.flow.Flow

@SpringService
class Main {
    private val thing: B = B()
    fun stream(): Flow<Int> = TODO()
}
